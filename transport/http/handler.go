package http

import (
	"context"
	"threatservice/internal/domain"
	"threatservice/internal/threat"
	"threatservice/transport/http/api"
)

type Handler struct{ service *threat.Service }

var _ api.StrictServerInterface = (*Handler)(nil)

func input(name string, description *string, kind *api.ThreatType, severity *api.Severity, platforms *[]api.Platform) domain.Input {
	in := domain.Input{Name: name, Description: description}
	if kind != nil {
		in.Type = string(*kind)
	}
	if severity != nil {
		in.Severity = string(*severity)
	}
	if platforms != nil {
		for _, v := range *platforms {
			in.Platforms = append(in.Platforms, string(v))
		}
	}
	return in
}
func output(t domain.Threat) api.ThreatResponse {
	p := make([]api.Platform, 0, len(t.Platforms))
	for _, v := range t.Platforms {
		p = append(p, api.Platform(v))
	}
	return api.ThreatResponse{Md5: t.MD5, Name: t.Name, Description: t.Description, Type: api.ThreatType(t.Type), Severity: api.Severity(t.Severity), Platforms: p, FirstSeenAt: t.FirstSeenAt, CreatedAt: &t.CreatedAt, UpdatedAt: &t.UpdatedAt}
}
func (h *Handler) CreateThreat(ctx context.Context, r api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	if r.Body == nil {
		return nil, domain.ErrInvalid
	}
	b := r.Body
	in := input(b.Name, b.Description, b.Type, b.Severity, b.Platforms)
	in.FirstSeenAt = b.FirstSeenAt
	t, err := h.service.Create(ctx, b.Md5, in)
	if err != nil {
		return nil, err
	}
	return api.CreateThreat201JSONResponse(output(t)), nil
}
func (h *Handler) UpdateThreat(ctx context.Context, r api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	if r.Body == nil {
		return nil, domain.ErrInvalid
	}
	b := r.Body
	in := input(b.Name, b.Description, b.Type, b.Severity, b.Platforms)
	in.FirstSeenAt = b.FirstSeenAt
	t, err := h.service.Update(ctx, r.Md5, in)
	if err != nil {
		return nil, err
	}
	return api.UpdateThreat200JSONResponse(output(t)), nil
}
func (h *Handler) GetInfoByMd5(ctx context.Context, r api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	t, err := h.service.Get(ctx, r.Md5)
	if err != nil {
		return nil, err
	}
	return api.GetInfoByMd5200JSONResponse(output(t)), nil
}
func (h *Handler) ListThreats(ctx context.Context, r api.ListThreatsRequestObject) (api.ListThreatsResponseObject, error) {
	f := domain.Filter{Limit: 20}
	if r.Params.Limit != nil {
		f.Limit = *r.Params.Limit
	}
	if r.Params.Offset != nil {
		f.Offset = *r.Params.Offset
	}
	if r.Params.Platforms != nil {
		for _, p := range *r.Params.Platforms {
			f.Platforms = append(f.Platforms, string(p))
		}
	}
	page, err := h.service.List(ctx, f)
	if err != nil {
		return nil, err
	}
	items := make([]api.ThreatResponse, 0, len(page.Items))
	for _, t := range page.Items {
		items = append(items, output(t))
	}
	return api.ListThreats200JSONResponse{Items: items, Limit: page.Limit, Offset: page.Offset, HasMore: page.HasMore}, nil
}
