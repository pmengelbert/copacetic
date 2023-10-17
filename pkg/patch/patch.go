// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package patch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/distribution/reference"
	"github.com/moby/buildkit/client"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/project-copacetic/copacetic/pkg/buildkit"
	"github.com/project-copacetic/copacetic/pkg/pkgmgr"
	"github.com/project-copacetic/copacetic/pkg/report"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	"github.com/project-copacetic/copacetic/pkg/vex"
)

const (
	defaultPatchedTagSuffix = "patched"
	copaProduct             = "copa"
)

// Patch command applies package updates to an OCI image given a vulnerability report.
func Patch(ctx context.Context, timeout time.Duration, image, reportFile, patchedTag, workingFolder, format, output string, ignoreError bool, bkOpts buildkit.Opts) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ch := make(chan error)
	go func() {
		ch <- patchWithContext(timeoutCtx, image, reportFile, patchedTag, workingFolder, format, output, ignoreError, bkOpts)
	}()

	select {
	case err := <-ch:
		return err
	case <-timeoutCtx.Done():
		// add a grace period for long running deferred cleanup functions to complete
		<-time.After(1 * time.Second)

		err := fmt.Errorf("patch exceeded timeout %v", timeout)
		log.Error(err)
		return err
	}
}

func removeIfNotDebug(workingFolder string) {
	if log.GetLevel() >= log.DebugLevel {
		// Keep the intermediate outputs for outputs solved to working folder if debugging
		log.Warnf("--debug specified, working folder at %s needs to be manually cleaned up", workingFolder)
	} else {
		os.RemoveAll(workingFolder)
	}
}

func patchWithContext(ctx context.Context, image, reportFile, patchedTag, workingFolder, format, output string, ignoreError bool, bkOpts buildkit.Opts) error {
	imageName, err := reference.ParseNamed(image)
	if err != nil {
		return err
	}
	if reference.IsNameOnly(imageName) {
		log.Warnf("Image name has no tag or digest, using latest as tag")
		imageName = reference.TagNameOnly(imageName)
	}
	taggedName, ok := imageName.(reference.Tagged)
	if !ok {
		err := errors.New("unexpected: TagNameOnly did create Tagged ref")
		log.Error(err)
		return err
	}
	tag := taggedName.Tag()
	if patchedTag == "" {
		if tag == "" {
			log.Warnf("No output tag specified for digest-referenced image, defaulting to `%s`", defaultPatchedTagSuffix)
			patchedTag = defaultPatchedTagSuffix
		} else {
			patchedTag = fmt.Sprintf("%s-%s", tag, defaultPatchedTagSuffix)
		}
	}
	patchedImageName := fmt.Sprintf("%s:%s", imageName.Name(), patchedTag)

	// Ensure working folder exists for call to InstallUpdates
	if workingFolder == "" {
		var err error
		workingFolder, err = os.MkdirTemp("", "copa-*")
		if err != nil {
			return err
		}
		defer removeIfNotDebug(workingFolder)
		if err = os.Chmod(workingFolder, 0o744); err != nil {
			return err
		}
	} else {
		if isNew, err := utils.EnsurePath(workingFolder, 0o744); err != nil {
			log.Errorf("failed to create workingFolder %s", workingFolder)
			return err
		} else if isNew {
			defer removeIfNotDebug(workingFolder)
		}
	}

	// Parse report for update packages
	updates, err := report.TryParseScanReport(reportFile)
	if err != nil {
		return err
	}
	log.Debugf("updates to apply: %v", updates)

	bkClient, err := buildkit.NewClient(ctx, bkOpts)
	if err != nil {
		return err
	}
	// defer bkClient.Close()

	var bkConfig buildkit.Config
	eg, _ := errgroup.WithContext(ctx)

	eg.Go(func() error {
		// Configure buildctl/client for use by package manager

		_, err = bkClient.Build(ctx, client.SolveOpt{}, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
			return c.Solve(ctx, gwclient.SolveRequest{Evaluate: true})
		}, nil)

		return err
	})
	if err := eg.Wait(); err != nil {
		return err
	}

	// solveOpts := client.SolveOpt{
	// 	Exports: []client.ExportEntry{
	// 		{
	// 			Type: "moby",
	// 			Attrs: map[string]string{
	// 				"name": tag,
	// 				// Pass through resolved configData from original image
	// 				exptypes.ExporterImageConfigKey: string(bkConfig.ConfigData),
	// 			},
	// 		},
	// 	},
	// 	Ref: patchedImageName,
	// }

	_, err = bkClient.Build(ctx, client.SolveOpt{}, copaProduct, func(ctx context.Context, c gwclient.Client) (*gwclient.Result, error) {
		config, err := buildkit.InitializeBuildkitConfig(ctx, c, image, updates)
		if err != nil {
			return nil, err
		}

		bkConfig = *config
		// Create package manager helper
		pkgmgr, err := pkgmgr.GetPackageManager(updates.OSType, &bkConfig, workingFolder)
		if err != nil {
			return nil, err
		}

		// Export the patched image state to Docker
		// TODO: Add support for other output modes as buildctl does.
		patchedImageState, errPkgs, err := pkgmgr.InstallUpdates(ctx, updates, ignoreError)
		if err != nil {
			return nil, err
		}

		def, err := patchedImageState.Marshal(ctx)
		if err != nil {
			return nil, err
		}

		solveResp, solveErr := c.Solve(ctx, gwclient.SolveRequest{
			Evaluate:   true,
			Definition: def.ToPB(),
		})
		if err != nil {
			return nil, err
		}
		// _ = patchedImageName
		if err := buildkit.SolveToDocker(ctx, bkClient, patchedImageState, bkConfig.ConfigData, patchedImageName); err != nil {
			return nil, err
		}

		// create a new manifest with the successfully patched packages
		validatedManifest := &types.UpdateManifest{
			OSType:    updates.OSType,
			OSVersion: updates.OSVersion,
			Arch:      updates.Arch,
			Updates:   []types.UpdatePackage{},
		}
		for _, update := range updates.Updates {
			if !slices.Contains(errPkgs, update.Name) {
				validatedManifest.Updates = append(validatedManifest.Updates, update)
			}
		}

		// vex document must contain at least one statement
		if output != "" && len(validatedManifest.Updates) > 0 {
			if err := vex.TryOutputVexDocument(validatedManifest, pkgmgr, format, output); err != nil {
				return nil, err
			}

			return nil, nil
		}

		return solveResp, solveErr
	}, nil)

	return err
}
