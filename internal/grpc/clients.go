package grpc

import (
	"fmt"

	"github.com/codec404/Konfig/pkg/pb"
	"github.com/codec404/konfig-web-backend/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Clients holds all gRPC client connections and their stub clients.
type Clients struct {
	APIConn  *grpc.ClientConn
	DistConn *grpc.ClientConn
	ValConn  *grpc.ClientConn
	API      pb.ConfigAPIServiceClient
	Dist     pb.DistributionServiceClient
	Val      pb.ValidationServiceClient
}

// NewClients initialises gRPC connections to all three Konfig services.
func NewClients(cfg *config.Config) (*Clients, error) {
	apiConn, err := grpc.NewClient(cfg.KonfigAPIAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial API service at %s: %w", cfg.KonfigAPIAddr, err)
	}

	distConn, err := grpc.NewClient(cfg.KonfigDistAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		apiConn.Close()
		return nil, fmt.Errorf("dial Distribution service at %s: %w", cfg.KonfigDistAddr, err)
	}

	valConn, err := grpc.NewClient(cfg.KonfigValAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		apiConn.Close()
		distConn.Close()
		return nil, fmt.Errorf("dial Validation service at %s: %w", cfg.KonfigValAddr, err)
	}

	return &Clients{
		APIConn:  apiConn,
		DistConn: distConn,
		ValConn:  valConn,
		API:      pb.NewConfigAPIServiceClient(apiConn),
		Dist:     pb.NewDistributionServiceClient(distConn),
		Val:      pb.NewValidationServiceClient(valConn),
	}, nil
}

// Close closes all underlying gRPC connections.
func (c *Clients) Close() {
	if c.APIConn != nil {
		c.APIConn.Close()
	}
	if c.DistConn != nil {
		c.DistConn.Close()
	}
	if c.ValConn != nil {
		c.ValConn.Close()
	}
}
