package rimaudit

import (
	"context"
	"strings"
	"time"

	auditv1 "buf.build/gen/go/rimdesk/audit-api/protocolbuffers/go/rimdesk/audit/v1"
	commonv1 "buf.build/gen/go/rimdesk/common/protocolbuffers/go/rimdesk/common/v1"
	"connectrpc.com/connect"
	"github.com/beego/beego/v2/core/logs"
	"github.com/rimdesk/rimcore-go/rimcore"
	"github.com/rimdesk/rimnats-go"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Audit interface {
	// UnaryAuditInterceptor returns a Connect RPC interceptor that publishes audit events for requests
	// using the provided NATS client publisher. It captures the service name and version for audit trail purposes.
	UnaryAuditInterceptor(publisher rimnats.Client) connect.UnaryInterceptorFunc
}

type auditImpl struct {
	logger        *logs.BeeLogger
	contextHelper rimcore.ContextHelper
	resolver      rimcore.ResourceResolver
}

// UnaryAuditInterceptor returns a Connect interceptor that captures and publishes
// audit events for all gRPC requests. It records service name, action, actor details,
// resource information, request/response data, and timing information.
//
// The audit event is published asynchronously to avoid blocking the request flow.
// Events are sent via the provided NATS publisher to the "event.create" subject.
//
// The interceptor extracts tenant and user information from the request context,
// resolves the resource and action from the procedure name, and constructs an
// AuditRequest message compliant with audit API v1 specification.
//
// Parameters:
//   - publisher: NATS client for publishing audit events
//
// Returns a UnaryInterceptorFunc that can be chained with other interceptors.
func (middleware *auditImpl) UnaryAuditInterceptor(publisher rimnats.Client) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()

			// Call actual handler
			resp, err := next(ctx, req)
			procedure := req.Spec().Procedure

			procedure = strings.TrimPrefix(procedure, "/")
			parts := strings.Split(procedure, "/")

			var serviceName, _ string
			if len(parts) != 2 {
				serviceName, _ = "unknown", "unknown"
			}

			_, resource, action, _ := middleware.resolver.Resolve(req.Spec().Procedure)
			traceID := middleware.contextHelper.GetTraceID(ctx)
			requestID := middleware.contextHelper.GetRequestID(ctx)

			serviceFull := parts[0] // rimdesk.inventory.v1.InventoryService
			_ = parts[1]

			serviceParts := strings.Split(serviceFull, ".")
			serviceName = serviceParts[len(serviceParts)-1] // InventoryService

			tenant, _ := middleware.contextHelper.GetTenant(ctx)
			userClaims := middleware.contextHelper.GetUserClaims(ctx)

			// Build audit event
			event := &auditv1.AuditRequest{
				Version:     auditv1.AuditVersion_AUDIT_VERSION_V1,
				TenantId:    tenant,
				ServiceName: serviceName,
				FullService: procedure,
				Action:      action,
				TraceId:     traceID,
				RequestId:   requestID,
				OccurredAt:  timestamppb.New(start),
			}

			// Actor
			event.Actor = &commonv1.Actor{
				Id:   userClaims.Id,
				Type: commonv1.ActorType_ACTOR_TYPE_USER,
				Role: userClaims.GetRole(),
			}

			// Resource
			event.Resource = &auditv1.Resource{
				Type: resource,
				Id:   "",
			}

			// Convert request/response to struct
			beforeStruct, _ := structpb.NewStruct(map[string]interface{}{
				"request": req,
			})

			afterStruct, _ := structpb.NewStruct(map[string]interface{}{
				"response": resp,
			})

			event.Before = beforeStruct
			event.After = afterStruct

			// Async publish (non-blocking)
			go func(auditRequest *auditv1.AuditRequest) {
				publishCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				createAuditRequest := &auditv1.CreateAuditRequest{Audit: auditRequest}

				if err := publisher.Publish(publishCtx, "audit.create", createAuditRequest); err != nil {
					middleware.logger.Error("Failed to publish audit event: %v", err)
				}
			}(event)

			return resp, err
		}
	}
}

func New(
	logger *logs.BeeLogger,
	contextHelper rimcore.ContextHelper,
	resolver rimcore.ResourceResolver,
) Audit {
	return &auditImpl{
		contextHelper: contextHelper,
		logger:        logger,
		resolver:      resolver,
	}
}
