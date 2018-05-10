package utils

import (
	"context"
	"os"
	"os/signal"
	"time"
)

type Shutdownable interface {
	Shutdown(ctx context.Context) error
}

func GracefullShutdown(s Shutdownable) error {
	stop := make(chan os.Signal)
	signal.Notify(stop, os.Interrupt)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	err := s.Shutdown(ctx)
	if err != nil {
		return err
	}
	return nil
}
