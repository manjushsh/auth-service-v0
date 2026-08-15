package admin

import (
	"context"
	"strconv"

	model "github.com/manjushsh/auth-service/internal/model/admin"
	store "github.com/manjushsh/auth-service/internal/store/auth"
)

// ListAudit reads the log. There is deliberately no write, update or delete
// counterpart: an audit log the application can rewrite is one an attacker who
// owns the application can rewrite. Retention belongs to a separate job with
// its own credentials.
func (s *Service) ListAudit(ctx context.Context, f store.AuditFilter) (model.AuditList, error) {
	f.Page = f.Page.Normalize()

	records, err := s.store.ListAudit(ctx, f)
	if err != nil {
		return model.AuditList{}, err
	}
	if records == nil {
		// Belt and braces against a future store returning nil: an empty page
		// must serialize as [] so clients can iterate it unconditionally.
		records = []store.AuditRecord{}
	}
	return model.AuditList{
		Records: records,
		NextCursor: nextCursor(records, f.Page.Limit, func(r store.AuditRecord) store.Cursor {
			return store.Cursor{Time: r.CreatedAt, ID: strconv.FormatInt(r.ID, 10)}
		}),
	}, nil
}
