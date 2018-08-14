package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/clair/api/v3/clairpb"
	"github.com/heroku/docker-registry-client/registry"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func getRegistryAuthToken(repository string) (string, error) {
	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repository)

	rsp, err := http.Get(url)
	if err != nil {
		log.WithError(err).Fatal("Failed to fetch token")
	}
	defer rsp.Body.Close()

	var authResponse struct {
		Token string
	}

	if err := json.NewDecoder(rsp.Body).Decode(&authResponse); err != nil {
		return "", err
	}

	return fmt.Sprintf("Bearer %s", authResponse.Token), nil
}

func main() {

	url := "https://registry-1.docker.io"
	username := ""
	password := ""
	repository := "tsaarni/docker-image-creator"
	tag := "latest"

	// fetch image manifest and manifest digest
	hub, err := registry.New(url, username, password)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to registry")
	}

	manifest, err := hub.Manifest(repository, tag)
	if err != nil {
		log.WithError(err).Fatal("Failed to fetch manifest")
	}

	digest, err := hub.ManifestDigest(repository, tag)
	if err != nil {
		log.WithError(err).Fatal("Failed to fetch manifest digest")
	}

	// docker-registry-client library does not expose authorization token, so fetch it again
	token, err := getRegistryAuthToken(repository)
	if err != nil {
		log.WithError(err).Fatal("Failed to authenticate")
	}

	// build request for clair to scan the filesystem layers in the image
	layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.FSLayers))
	for i, l := range manifest.FSLayers {
		layers[i] = &clairpb.PostAncestryRequest_PostLayer{
			Hash:    l.BlobSum.Encoded(),
			Path:    strings.Join([]string{url, "v2", repository, "blobs", l.BlobSum.Encoded()}, "/"),
			Headers: map[string]string{"Authorization": token},
		}
	}

	post := &clairpb.PostAncestryRequest{
		Format:       "Docker",
		AncestryName: digest.Encoded(),
		Layers:       layers,
	}

	// connect to clair
	conn, err := grpc.Dial("localhost:6060", grpc.WithInsecure())
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to clair")
	}

	clair := clairpb.NewAncestryServiceClient(conn)

	// send request
	_, err = clair.PostAncestry(context.Background(), post)
	if err != nil {
		log.WithError(err).Fatal("Failed to push ancestry")
	}

	// build request to list the vulnerabilities
	get := &clairpb.GetAncestryRequest{
		AncestryName:        digest.Encoded(),
		WithFeatures:        true,
		WithVulnerabilities: true,
	}

	rsp, err := clair.GetAncestry(context.Background(), get)
	if err != nil {
		log.WithError(err).Fatal("Failed to get ancestry")
	}

	for _, f := range rsp.Ancestry.Features {
		for _, v := range f.GetVulnerabilities() {
			fmt.Printf("%+v\n", v)
		}
	}
}
