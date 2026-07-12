package route

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/component/diagnostic"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

var diagnosticManager = diagnostic.NewManager(func(name string) (C.Dialer, bool, error) {
	proxy, ok := tunnel.Proxies()[name]
	if !ok {
		return nil, false, fmt.Errorf("proxy %q not found", name)
	}
	return proxydialer.New(proxy, true), proxy.SupportUDP(), nil
})

func diagnosticRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/capabilities", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, render.M{"profiles": []string{"game", "web", "video"}, "maxConcurrentRuns": 4, "doesNotSwitchProxy": true})
	})
	r.Get("/runs", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, render.M{"runs": diagnosticManager.List()})
	})
	r.Post("/runs", startDiagnostic)
	r.Route("/runs/{id}", func(r chi.Router) { r.Get("/", getDiagnostic); r.Delete("/", cancelDiagnostic) })
	return r
}

func startDiagnostic(w http.ResponseWriter, r *http.Request) {
	var request diagnostic.StartRequest
	if err := render.DecodeJSON(r.Body, &request); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	run, err := diagnosticManager.Start(request)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, diagnostic.ErrBusy) {
			status = http.StatusConflict
		}
		render.Status(r, status)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.Status(r, http.StatusAccepted)
	render.JSON(w, r, run)
}
func getDiagnostic(w http.ResponseWriter, r *http.Request) {
	run, err := diagnosticManager.Get(getEscapeParam(r, "id"))
	if errors.Is(err, diagnostic.ErrNotFound) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}
	render.JSON(w, r, run)
}
func cancelDiagnostic(w http.ResponseWriter, r *http.Request) {
	err := diagnosticManager.Cancel(getEscapeParam(r, "id"))
	if errors.Is(err, diagnostic.ErrNotFound) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}
	render.NoContent(w, r)
}
