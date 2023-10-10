// ------------------------------------------------------------
// Copyright (c) Project Copacetic authors.
// Licensed under the MIT License.
// ------------------------------------------------------------

package buildkit

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"

	"github.com/containerd/containerd/remotes/docker"
	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/exporter/containerimage/image"
	"github.com/moby/buildkit/frontend/dockerui"
	gwclient "github.com/moby/buildkit/frontend/gateway/client"
	"github.com/moby/buildkit/util/contentutil"
	"github.com/moby/buildkit/util/imageutil"
	"github.com/moby/buildkit/version"
	"github.com/opencontainers/go-digest"
	ispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/project-copacetic/copacetic/pkg/types"
	"github.com/project-copacetic/copacetic/pkg/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type Config struct {
	ImageName  string
	Client     gwclient.Client
	ConfigData []byte
	Platform   ispec.Platform
	ImageState llb.State
}

type Opts struct {
	Addr       string
	CACertPath string
	CertPath   string
	KeyPath    string
}

func dockerLoad(ctx context.Context, pipeR io.Reader) error {
	cmd := exec.CommandContext(ctx, "docker", "load")
	cmd.Stdin = pipeR

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	// Pipe run errors to WarnLevel since execution continues asynchronously
	// Caller should log a separate ErrorLevel on completion based on err
	go utils.LogPipe(stderr, log.WarnLevel)
	go utils.LogPipe(stdout, log.InfoLevel)

	return cmd.Run()
}

// Custom ResolveImageConfig implementation for using Docker default config.json credentials
// to pull image config.
//
// While it would be ideal to be able to use imagemetaresolver.Default().ResolveImageConfig(),
// there doesn't seem to be a way to configure the necessary DockerAuthorizer or RegistryHosts
// against an ImageMetaResolver, which causes the resolve to only use anonymous tokens and fail.
func resolveImageConfig(ctx context.Context, ref string, platform *ispec.Platform) (digest.Digest, []byte, error) {
	auth := docker.NewDockerAuthorizer(
		docker.WithAuthCreds(func(ref string) (string, string, error) {
			defaultConfig := config.LoadDefaultConfigFile(os.Stderr)
			ac, err := defaultConfig.GetAuthConfig(ref)
			if err != nil {
				return "", "", err
			}
			if ac.IdentityToken != "" {
				return "", ac.IdentityToken, nil
			}
			return ac.Username, ac.Password, nil
		}))
	hosts := docker.ConfigureDefaultRegistries(
		docker.WithClient(http.DefaultClient),
		docker.WithPlainHTTP(docker.MatchLocalhost),
		docker.WithAuthorizer(auth),
	)

	headers := http.Header{}
	headers.Set("User-Agent", version.UserAgent())
	resolver := docker.NewResolver(docker.ResolverOptions{
		Client:  http.DefaultClient,
		Headers: headers,
		Hosts:   hosts,
	})

	_, dgst, config, err := imageutil.Config(ctx, ref, resolver, contentutil.NewBuffer(), nil, platform, nil)
	if err != nil {
		return "", nil, err
	}
	return dgst, config, nil
}

func InitializeBuildkitConfig(ctx context.Context, c gwclient.Client, image string, configData []byte, manifest *types.UpdateManifest) (*Config, error) {
	// Initialize buildkit config for the target image
	config := Config{
		ImageName: image,
		Platform: ispec.Platform{
			OS:           "linux",
			Architecture: manifest.Arch,
		},
	}

	// Load the target image state with the resolved image config in case environment variable settings
	// are necessary for running apps in the target image for updates
	var err error
	config.ImageState, err = llb.Image(image,
		llb.Platform(config.Platform),
		llb.WithMetaResolver(c),
		llb.ResolveModePreferLocal,
	).WithImageConfig(configData)

	if err != nil {
		return nil, err
	}

	config.Client = c
	config.ConfigData = configData

	return &config, nil
}

func SolveToLocal(ctx context.Context, c gwclient.Client, st *llb.State, outPath string) ([]byte, error) {
	def, err := st.Marshal(ctx)
	if err != nil {
		log.Errorf("st.Marshal failed with %s", err)
		return nil, err
	}

	var b []byte
	// _, err := c.Solve(ctx)
	resp, err := c.Solve(ctx, gwclient.SolveRequest{
		Evaluate:   true,
		Definition: def.ToPB(),
	})
	if err != nil {
		return nil, err
	}

	a, err := resp.SingleRef()
	if err != nil {
		return nil, err
	}

	b, err = a.ReadFile(ctx, gwclient.ReadRequest{
		Filename: "/copa-out/results.manifest",
	})
	if err != nil {
		return nil, err
	}

	log.Debugf("Wrote LLB state to %s", outPath)
	return b, nil
}

func SolveToDocker(ctx context.Context, c gwclient.Client, st *llb.State, configData []byte, tag string) error {
	def, err := st.Marshal(ctx)
	if err != nil {
		log.Errorf("st.Marshal failed with %s", err)
		return err
	}

	// pipeR, pipeW := io.Pipe()
	// dockerConfig := config.LoadDefaultConfigFile(os.Stderr)
	// attachable := []session.Attachable{authprovider.NewDockerAuthProvider(dockerConfig)}
	// solveOpt := client.SolveOpt{
	// 	Exports: []client.ExportEntry{
	// 		{
	// 			Type: client.ExporterDocker,
	// 			Attrs: map[string]string{
	// 				"name": tag,
	// 				// Pass through resolved configData from original image
	// 				exptypes.ExporterImageConfigKey: string(configData),
	// 			},
	// 			Output: func(_ map[string]string) (io.WriteCloser, error) {
	// 				return pipeW, nil
	// 			},
	// 		},
	// 	},
	// 	Frontend: "",         // i.e. we are passing in the llb.Definition directly
	// 	Session:  attachable, // used for authprovider, sshagentprovider and secretprovider
	// }

	// ch := make(chan *client.SolveStatus)
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		dc, err := dockerui.NewClient(c)
		if err != nil {
			return err
		}

		rb, err := dc.Build(ctx, func(ctx context.Context, platform *ispec.Platform, idx int) (gwclient.Reference, *image.Image, error) {
			r, err := c.Solve(ctx, gwclient.SolveRequest{
				Evaluate:   true,
				Definition: def.ToPB(),
			})
			if err != nil {
				return nil, nil, err
			}

			ref, err := r.SingleRef()
			if err != nil {
				return nil, nil, err
			}

			return ref, nil, nil
		})
		if err != nil {
			return err
		}

		if _, err := rb.Finalize(); err != nil {
			return err
		}

		return nil
	})
	return eg.Wait()
}
