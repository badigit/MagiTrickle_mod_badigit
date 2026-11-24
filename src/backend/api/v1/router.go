package v1

import (
	"net/http"

	"magitrickle/api/auth"
	"magitrickle/api/utils"
	"magitrickle/app"
	"magitrickle/utils/intID"

	"github.com/go-chi/chi/v5"
)

// NewRouter собирает маршруты API v1
func NewRouter(a app.Main) chi.Router {
	h := NewHandler(a)
	r := chi.NewRouter()
	r.Get("/auth", auth.StatusHandler(a))
	r.Post("/auth", auth.LoginHandler(a))
	r.Get("/subscriptions", h.GetSubscriptions)
	r.Put("/subscriptions", h.PutSubscriptions)
	r.Post("/subscription", h.CreateSubscription)
	r.Patch("/subscription", h.SyncSubscription)
	r.Delete("/subscription", h.DeleteSubscription)
	r.Get("/subscription/rules", h.PreviewSubscriptionRules)
	r.Route("/groups", func(r chi.Router) {
		r.Get("/", h.GetGroups)
		r.Put("/", h.PutGroups)
		r.Post("/", h.CreateGroup)
		r.Route("/{groupID}", func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					groupID := chi.URLParam(r, "groupID")
					id, err := intID.ParseID(groupID)
					if err != nil {
						utils.WriteError(w, http.StatusBadRequest, "invalid group id")
						return
					}
					for _, group := range h.app.Groups() {
						if group.Model().ID == id {
							next.ServeHTTP(w, r)
							return
						}
					}
					utils.WriteError(w, http.StatusNotFound, "group not exist")
				})
			})
			r.Get("/", h.GetGroup)
			r.Put("/", h.PutGroup)
			r.Delete("/", h.DeleteGroup)
			r.Route("/rules", func(r chi.Router) {
				r.Get("/", h.GetRules)
				r.Put("/", h.PutRules)
				r.Post("/", h.CreateRule)
				r.Route("/{ruleID}", func(r chi.Router) {
					r.Get("/", h.GetRule)
					r.Put("/", h.PutRule)
					r.Delete("/", h.DeleteRule)
				})
			})
		})
	})
	r.Route("/system", func(r chi.Router) {
		r.Get("/client-routing", h.GetClientRouting)
		r.Get("/direct-priority", h.GetDirectPriority)
		r.Put("/direct-priority", h.PutDirectPriority)
		r.Put("/client-routing", h.PutClientRouting)
		r.Route("/interfaces", func(r chi.Router) {
			r.Get("/", h.ListInterfaces)
			r.Get("/aliases", h.ListInterfaceAliases)
			r.Post("/aliases", h.SaveInterfaceAliases)
			r.Get("/{interfaceID}/external-ip", h.GetExternalIP)
		})
		r.Route("/config", func(r chi.Router) {
			r.Post("/save", h.SaveConfig)
		})
		r.Route("/dns-capture", func(r chi.Router) {
			r.Post("/start", h.StartDNSCapture)
			r.Post("/stop", h.StopDNSCapture)
			r.Get("/status", h.GetDNSCaptureStatus)
		})
		r.Get("/tproxy-status", h.GetTProxyStatus)
		r.Post("/restart", h.RestartService)
		r.Get("/info", h.GetSystemInfo)
		r.Get("/enabled", h.GetEnabled)
		r.Post("/enabled", h.SetEnabled)
		r.Route("/update", func(r chi.Router) {
			r.Get("/check", h.CheckUpdate)
			r.Post("/run", h.RunUpdate)
			r.Get("/status", h.UpdateStatus)
			r.Get("/log", h.UpdateLog)
		})
		r.Route("/hooks", func(r chi.Router) {
			r.Post("/netfilterd", h.NetfilterDHook)
		})
	})
	r.Post("/lookup", h.Lookup)
	r.Post("/warmup", h.Warmup)
	r.Route("/diagnostics", func(r chi.Router) {
		r.Get("/speedtest", h.RunSpeedtest)
		r.Get("/speedtest/servers", h.GetSpeedtestServers)
	})
	return r
}
