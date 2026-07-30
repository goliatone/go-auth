package main

import (
	"context"
	"fmt"
	"path"

	"github.com/goliatone/go-admin/admin"
	"github.com/goliatone/go-admin/quickstart"
	"github.com/uptrace/bun"
)

type providerIdentityCounter interface {
	CountProviderIdentities(context.Context, string) (int, error)
}

type bunProviderIdentityCounter struct {
	db *bun.DB
}

func (c bunProviderIdentityCounter) CountProviderIdentities(ctx context.Context, provider string) (int, error) {
	if c.db == nil {
		return 0, fmt.Errorf("database is required")
	}
	return c.db.NewSelect().
		Table("user_identifiers").
		Where("provider = ?", provider).
		Count(ctx)
}

type linkedIdentityWidgetConfig struct {
	Title string `json:"title"`
}

func registerDashboard(adm *admin.Admin, cfg admin.Config, counter providerIdentityCounter) {
	placements := quickstart.DefaultPlacements(cfg)
	mainArea := quickstart.ResolveDashboardArea(placements, "main", "admin.dashboard.main")
	sidebarArea := quickstart.ResolveDashboardArea(placements, "sidebar", "admin.dashboard.sidebar")

	adm.Dashboard().RegisterProvider(linkedIdentityProvider(counter, mainArea))
	adm.Dashboard().RegisterProvider(supabaseActionsProvider(sidebarArea))
}

func linkedIdentityProvider(counter providerIdentityCounter, area string) admin.DashboardProviderSpec {
	return admin.DashboardProviderSpec{
		Code:          admin.WidgetUserStats,
		Name:          "Supabase linked identities",
		Description:   "Local identities linked through the Supabase OIDC callback.",
		DefaultArea:   area,
		DefaultSpan:   4,
		DefaultConfig: map[string]any{"title": "Supabase linked identities"},
		Handler: func(ctx admin.AdminContext, raw map[string]any) (admin.WidgetPayload, error) {
			cfg, err := admin.DecodeWidgetConfig[linkedIdentityWidgetConfig](raw)
			if err != nil {
				return admin.WidgetPayload{}, err
			}
			count, err := counter.CountProviderIdentities(ctx.Context, "supabase")
			if err != nil {
				return admin.WidgetPayload{}, err
			}
			return admin.WidgetPayloadOf(admin.UserStatsWidgetPayload{
				Title:  cfg.Title,
				Metric: "linked_identities",
				Value:  count,
			}), nil
		},
	}
}

func supabaseActionsProvider(area string) admin.DashboardProviderSpec {
	return admin.DashboardProviderSpec{
		Code:        admin.WidgetQuickActions,
		Name:        "Supabase integration",
		Description: "Safe browser entry points for the configured Supabase provider.",
		DefaultArea: area,
		DefaultSpan: 4,
		Handler: func(_ admin.AdminContext, raw map[string]any) (admin.WidgetPayload, error) {
			if _, err := admin.DecodeWidgetConfig[struct{}](raw); err != nil {
				return admin.WidgetPayload{}, err
			}
			return admin.WidgetPayloadOf(admin.QuickActionsWidgetPayload{
				Actions: []admin.QuickActionWidgetPayload{
					{
						Label:       "Reauthenticate with Supabase",
						URL:         "/admin/sso/login/supabase?redirect_to=/admin/dashboard",
						Icon:        "refresh-cw",
						Method:      "GET",
						Description: "Run the OIDC authorization-code flow again.",
					},
					{
						Label:       "Inspect public provider metadata",
						URL:         path.Join("/admin/sso", "providers"),
						Icon:        "shield-check",
						Method:      "GET",
						Description: "View the secret-free provider list returned by the adapter.",
					},
				},
			}), nil
		},
	}
}
