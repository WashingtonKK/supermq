// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	authzSvcName  = "magistrala.AuthzService"
	authnSvcName  = "magistrala.AuthnService"
	policySvcName = "magistrala.PolicyService"
)

var (
	_ AuthServiceClient              = (*authGrpcClient)(nil)
	_ magistrala.PolicyServiceClient = (*policyGrpcClient)(nil)
)

//go:generate mockery --name AuthServiceClient --output=../../mocks --filename auth_client.go --quiet --note "Copyright (c) Abstract Machines"
type AuthServiceClient interface {
	magistrala.AuthzServiceClient
	magistrala.AuthnServiceClient
}

type authGrpcClient struct {
	issue     endpoint.Endpoint
	refresh   endpoint.Endpoint
	identify  endpoint.Endpoint
	authorize endpoint.Endpoint
	timeout   time.Duration
}

// NewAuthClient returns new auth gRPC client instance.
func NewAuthClient(conn *grpc.ClientConn, timeout time.Duration) AuthServiceClient {
	return &authGrpcClient{
		issue: kitgrpc.NewClient(
			conn,
			authnSvcName,
			"Issue",
			encodeIssueRequest,
			decodeIssueResponse,
			magistrala.Token{},
		).Endpoint(),
		refresh: kitgrpc.NewClient(
			conn,
			authnSvcName,
			"Refresh",
			encodeRefreshRequest,
			decodeRefreshResponse,
			magistrala.Token{},
		).Endpoint(),
		identify: kitgrpc.NewClient(
			conn,
			authnSvcName,
			"Identify",
			encodeIdentifyRequest,
			decodeIdentifyResponse,
			magistrala.IdentityRes{},
		).Endpoint(),
		authorize: kitgrpc.NewClient(
			conn,
			authzSvcName,
			"Authorize",
			encodeAuthorizeRequest,
			decodeAuthorizeResponse,
			magistrala.AuthorizeRes{},
		).Endpoint(),
		timeout: timeout,
	}
}

func (client authGrpcClient) Issue(ctx context.Context, req *magistrala.IssueReq, _ ...grpc.CallOption) (*magistrala.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.issue(ctx, issueReq{
		userID:   req.GetUserId(),
		domainID: req.GetDomainId(),
		keyType:  auth.KeyType(req.GetType()),
	})
	if err != nil {
		return &magistrala.Token{}, decodeError(err)
	}
	return res.(*magistrala.Token), nil
}

func encodeIssueRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(issueReq)
	return &magistrala.IssueReq{
		UserId:   req.userID,
		DomainId: &req.domainID,
		Type:     uint32(req.keyType),
	}, nil
}

func decodeIssueResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	return grpcRes, nil
}

func (client authGrpcClient) Refresh(ctx context.Context, req *magistrala.RefreshReq, _ ...grpc.CallOption) (*magistrala.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.refresh(ctx, refreshReq{refreshToken: req.GetRefreshToken(), domainID: req.GetDomainId()})
	if err != nil {
		return &magistrala.Token{}, decodeError(err)
	}
	return res.(*magistrala.Token), nil
}

func encodeRefreshRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(refreshReq)
	return &magistrala.RefreshReq{RefreshToken: req.refreshToken, DomainId: &req.domainID}, nil
}

func decodeRefreshResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	return grpcRes, nil
}

func (client authGrpcClient) Identify(ctx context.Context, token *magistrala.IdentityReq, _ ...grpc.CallOption) (*magistrala.IdentityRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.identify(ctx, identityReq{token: token.GetToken()})
	if err != nil {
		return &magistrala.IdentityRes{}, decodeError(err)
	}
	ir := res.(identityRes)
	return &magistrala.IdentityRes{Id: ir.id, UserId: ir.userID, DomainId: ir.domainID}, nil
}

func encodeIdentifyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(identityReq)
	return &magistrala.IdentityReq{Token: req.token}, nil
}

func decodeIdentifyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.IdentityRes)
	return identityRes{id: res.GetId(), userID: res.GetUserId(), domainID: res.GetDomainId()}, nil
}

func (client authGrpcClient) Authorize(ctx context.Context, req *magistrala.AuthorizeReq, _ ...grpc.CallOption) (r *magistrala.AuthorizeRes, err error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.authorize(ctx, authReq{
		Domain:      req.GetDomain(),
		SubjectType: req.GetSubjectType(),
		Subject:     req.GetSubject(),
		SubjectKind: req.GetSubjectKind(),
		Relation:    req.GetRelation(),
		Permission:  req.GetPermission(),
		ObjectType:  req.GetObjectType(),
		Object:      req.GetObject(),
	})
	if err != nil {
		return &magistrala.AuthorizeRes{}, decodeError(err)
	}

	ar := res.(authorizeRes)
	return &magistrala.AuthorizeRes{Authorized: ar.authorized, Id: ar.id}, nil
}

func decodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.AuthorizeRes)
	return authorizeRes{authorized: res.Authorized, id: res.Id}, nil
}

func encodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(authReq)
	return &magistrala.AuthorizeReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		Subject:     req.Subject,
		SubjectKind: req.SubjectKind,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		Object:      req.Object,
	}, nil
}

type policyGrpcClient struct {
	addPolicy            endpoint.Endpoint
	addPolicies          endpoint.Endpoint
	deletePolicyFilter   endpoint.Endpoint
	deletePolicies       endpoint.Endpoint
	listObjects          endpoint.Endpoint
	listAllObjects       endpoint.Endpoint
	countObjects         endpoint.Endpoint
	listSubjects         endpoint.Endpoint
	listAllSubjects      endpoint.Endpoint
	countSubjects        endpoint.Endpoint
	listPermissions      endpoint.Endpoint
	deleteEntityPolicies endpoint.Endpoint
	timeout              time.Duration
}

// NewPolicyClient returns new policy gRPC client instance.
func NewPolicyClient(conn *grpc.ClientConn, timeout time.Duration) magistrala.PolicyServiceClient {
	return &policyGrpcClient{
		addPolicy: kitgrpc.NewClient(
			conn,
			policySvcName,
			"AddPolicy",
			encodeAddPolicyRequest,
			decodeAddPolicyResponse,
			magistrala.AddPolicyRes{},
		).Endpoint(),
		addPolicies: kitgrpc.NewClient(
			conn,
			policySvcName,
			"AddPolicies",
			encodeAddPoliciesRequest,
			decodeAddPoliciesResponse,
			magistrala.AddPoliciesRes{},
		).Endpoint(),
		deletePolicyFilter: kitgrpc.NewClient(
			conn,
			policySvcName,
			"DeletePolicyFilter",
			encodeDeletePolicyFilterRequest,
			decodeDeletePolicyFilterResponse,
			magistrala.DeletePolicyRes{},
		).Endpoint(),
		deletePolicies: kitgrpc.NewClient(
			conn,
			policySvcName,
			"DeletePolicies",
			encodeDeletePoliciesRequest,
			decodeDeletePoliciesResponse,
			magistrala.DeletePolicyRes{},
		).Endpoint(),
		listObjects: kitgrpc.NewClient(
			conn,
			policySvcName,
			"ListObjects",
			encodeListObjectsRequest,
			decodeListObjectsResponse,
			magistrala.ListObjectsRes{},
		).Endpoint(),
		listAllObjects: kitgrpc.NewClient(
			conn,
			policySvcName,
			"ListAllObjects",
			encodeListObjectsRequest,
			decodeListObjectsResponse,
			magistrala.ListObjectsRes{},
		).Endpoint(),
		countObjects: kitgrpc.NewClient(
			conn,
			policySvcName,
			"CountObjects",
			encodeCountObjectsRequest,
			decodeCountObjectsResponse,
			magistrala.CountObjectsRes{},
		).Endpoint(),
		listSubjects: kitgrpc.NewClient(
			conn,
			policySvcName,
			"ListSubjects",
			encodeListSubjectsRequest,
			decodeListSubjectsResponse,
			magistrala.ListSubjectsRes{},
		).Endpoint(),
		listAllSubjects: kitgrpc.NewClient(
			conn,
			policySvcName,
			"ListAllSubjects",
			encodeListSubjectsRequest,
			decodeListSubjectsResponse,
			magistrala.ListSubjectsRes{},
		).Endpoint(),
		countSubjects: kitgrpc.NewClient(
			conn,
			policySvcName,
			"CountSubjects",
			encodeCountSubjectsRequest,
			decodeCountSubjectsResponse,
			magistrala.CountSubjectsRes{},
		).Endpoint(),
		listPermissions: kitgrpc.NewClient(
			conn,
			policySvcName,
			"ListPermissions",
			encodeListPermissionsRequest,
			decodeListPermissionsResponse,
			magistrala.ListPermissionsRes{},
		).Endpoint(),
		deleteEntityPolicies: kitgrpc.NewClient(
			conn,
			policySvcName,
			"DeleteEntityPolicies",
			encodeDeleteEntityPoliciesRequest,
			decodeDeleteEntityPoliciesResponse,
			magistrala.DeletePolicyRes{},
		).Endpoint(),

		timeout: timeout,
	}
}

func (client policyGrpcClient) AddPolicy(ctx context.Context, in *magistrala.AddPolicyReq, opts ...grpc.CallOption) (*magistrala.AddPolicyRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.addPolicy(ctx, policyReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		SubjectKind: in.GetSubjectKind(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		ObjectKind:  in.GetObjectKind(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.AddPolicyRes{}, decodeError(err)
	}

	apr := res.(addPolicyRes)
	return &magistrala.AddPolicyRes{Added: apr.added}, nil
}

func decodeAddPolicyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.AddPolicyRes)
	return addPolicyRes{added: res.Added}, nil
}

func encodeAddPolicyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(policyReq)
	return &magistrala.AddPolicyReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		SubjectKind: req.SubjectKind,
		Subject:     req.Subject,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		ObjectKind:  req.ObjectKind,
		Object:      req.Object,
	}, nil
}

func (client policyGrpcClient) AddPolicies(ctx context.Context, in *magistrala.AddPoliciesReq, opts ...grpc.CallOption) (*magistrala.AddPoliciesRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	r := policiesReq{}
	if in.GetAddPoliciesReq() != nil {
		for _, mgApr := range in.GetAddPoliciesReq() {
			r = append(r, policyReq{
				Domain:      mgApr.GetDomain(),
				SubjectType: mgApr.GetSubjectType(),
				SubjectKind: mgApr.GetSubjectKind(),
				Subject:     mgApr.GetSubject(),
				Relation:    mgApr.GetRelation(),
				Permission:  mgApr.GetPermission(),
				ObjectType:  mgApr.GetObjectType(),
				ObjectKind:  mgApr.GetObjectKind(),
				Object:      mgApr.GetObject(),
			})
		}
	}

	res, err := client.addPolicies(ctx, r)
	if err != nil {
		return &magistrala.AddPoliciesRes{}, decodeError(err)
	}

	apr := res.(addPoliciesRes)
	return &magistrala.AddPoliciesRes{Added: apr.added}, nil
}

func decodeAddPoliciesResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.AddPoliciesRes)
	return addPoliciesRes{added: res.Added}, nil
}

func encodeAddPoliciesRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	reqs := grpcReq.(policiesReq)

	addPolicies := []*magistrala.AddPolicyReq{}

	for _, req := range reqs {
		addPolicies = append(addPolicies, &magistrala.AddPolicyReq{
			Domain:      req.Domain,
			SubjectType: req.SubjectType,
			SubjectKind: req.SubjectKind,
			Subject:     req.Subject,
			Relation:    req.Relation,
			Permission:  req.Permission,
			ObjectType:  req.ObjectType,
			ObjectKind:  req.ObjectKind,
			Object:      req.Object,
		})
	}
	return &magistrala.AddPoliciesReq{AddPoliciesReq: addPolicies}, nil
}

func (client policyGrpcClient) DeletePolicyFilter(ctx context.Context, in *magistrala.DeletePolicyFilterReq, opts ...grpc.CallOption) (*magistrala.DeletePolicyRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.deletePolicyFilter(ctx, policyReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		SubjectKind: in.GetSubjectKind(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		ObjectKind:  in.GetObjectKind(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.DeletePolicyRes{}, decodeError(err)
	}

	dpr := res.(deletePolicyRes)
	return &magistrala.DeletePolicyRes{Deleted: dpr.deleted}, nil
}

func decodeDeletePolicyFilterResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.DeletePolicyRes)
	return deletePolicyRes{deleted: res.GetDeleted()}, nil
}

func encodeDeletePolicyFilterRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(policyReq)
	return &magistrala.DeletePolicyFilterReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		SubjectKind: req.SubjectKind,
		Subject:     req.Subject,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		ObjectKind:  req.ObjectKind,
		Object:      req.Object,
	}, nil
}

func (client policyGrpcClient) DeletePolicies(ctx context.Context, in *magistrala.DeletePoliciesReq, opts ...grpc.CallOption) (*magistrala.DeletePolicyRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	r := policiesReq{}

	if in.GetDeletePoliciesReq() != nil {
		for _, mgApr := range in.GetDeletePoliciesReq() {
			r = append(r, policyReq{
				Domain:      mgApr.GetDomain(),
				SubjectType: mgApr.GetSubjectType(),
				SubjectKind: mgApr.GetSubjectKind(),
				Subject:     mgApr.GetSubject(),
				Relation:    mgApr.GetRelation(),
				Permission:  mgApr.GetPermission(),
				ObjectType:  mgApr.GetObjectType(),
				ObjectKind:  mgApr.GetObjectKind(),
				Object:      mgApr.GetObject(),
			})
		}
	}
	res, err := client.deletePolicies(ctx, r)
	if err != nil {
		return &magistrala.DeletePolicyRes{}, decodeError(err)
	}

	dpr := res.(deletePolicyRes)
	return &magistrala.DeletePolicyRes{Deleted: dpr.deleted}, nil
}

func decodeDeletePoliciesResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.DeletePolicyRes)
	return deletePolicyRes{deleted: res.GetDeleted()}, nil
}

func encodeDeletePoliciesRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	reqs := grpcReq.(policiesReq)

	deletePolicies := []*magistrala.DeletePolicyReq{}

	for _, req := range reqs {
		deletePolicies = append(deletePolicies, &magistrala.DeletePolicyReq{
			Domain:      req.Domain,
			SubjectType: req.SubjectType,
			SubjectKind: req.SubjectKind,
			Subject:     req.Subject,
			Relation:    req.Relation,
			Permission:  req.Permission,
			ObjectType:  req.ObjectType,
			ObjectKind:  req.ObjectKind,
			Object:      req.Object,
		})
	}
	return &magistrala.DeletePoliciesReq{DeletePoliciesReq: deletePolicies}, nil
}

func (client policyGrpcClient) ListObjects(ctx context.Context, in *magistrala.ListObjectsReq, opts ...grpc.CallOption) (*magistrala.ListObjectsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.listObjects(ctx, listObjectsReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.ListObjectsRes{}, decodeError(err)
	}

	lpr := res.(listObjectsRes)
	return &magistrala.ListObjectsRes{Policies: lpr.policies}, nil
}

func decodeListObjectsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.ListObjectsRes)
	return listObjectsRes{policies: res.GetPolicies()}, nil
}

func encodeListObjectsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(listObjectsReq)
	return &magistrala.ListObjectsReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		Subject:     req.Subject,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		Object:      req.Object,
	}, nil
}

func (client policyGrpcClient) ListAllObjects(ctx context.Context, in *magistrala.ListObjectsReq, opts ...grpc.CallOption) (*magistrala.ListObjectsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.listAllObjects(ctx, listObjectsReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.ListObjectsRes{}, decodeError(err)
	}

	lpr := res.(listObjectsRes)
	return &magistrala.ListObjectsRes{Policies: lpr.policies}, nil
}

func (client policyGrpcClient) CountObjects(ctx context.Context, in *magistrala.CountObjectsReq, opts ...grpc.CallOption) (*magistrala.CountObjectsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.countObjects(ctx, countObjectsReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.CountObjectsRes{}, decodeError(err)
	}

	cp := res.(countObjectsRes)
	return &magistrala.CountObjectsRes{Count: cp.count}, nil
}

func decodeCountObjectsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.CountObjectsRes)
	return countObjectsRes{count: res.GetCount()}, nil
}

func encodeCountObjectsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(countObjectsReq)
	return &magistrala.CountObjectsReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		Subject:     req.Subject,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		Object:      req.Object,
	}, nil
}

func (client policyGrpcClient) ListSubjects(ctx context.Context, in *magistrala.ListSubjectsReq, opts ...grpc.CallOption) (*magistrala.ListSubjectsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.listSubjects(ctx, listSubjectsReq{
		Domain:        in.GetDomain(),
		SubjectType:   in.GetSubjectType(),
		Subject:       in.GetSubject(),
		Relation:      in.GetRelation(),
		Permission:    in.GetPermission(),
		ObjectType:    in.GetObjectType(),
		Object:        in.GetObject(),
		NextPageToken: in.GetNextPageToken(),
	})
	if err != nil {
		return &magistrala.ListSubjectsRes{}, decodeError(err)
	}

	lpr := res.(listSubjectsRes)
	return &magistrala.ListSubjectsRes{Policies: lpr.policies}, nil
}

func decodeListSubjectsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.ListSubjectsRes)
	return listSubjectsRes{policies: res.GetPolicies()}, nil
}

func encodeListSubjectsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(listSubjectsReq)
	return &magistrala.ListSubjectsReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		Subject:     req.Subject,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		Object:      req.Object,
	}, nil
}

func (client policyGrpcClient) ListAllSubjects(ctx context.Context, in *magistrala.ListSubjectsReq, opts ...grpc.CallOption) (*magistrala.ListSubjectsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.listAllSubjects(ctx, listSubjectsReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.ListSubjectsRes{}, decodeError(err)
	}

	lpr := res.(listSubjectsRes)
	return &magistrala.ListSubjectsRes{Policies: lpr.policies}, nil
}

func (client policyGrpcClient) CountSubjects(ctx context.Context, in *magistrala.CountSubjectsReq, opts ...grpc.CallOption) (*magistrala.CountSubjectsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.countSubjects(ctx, countSubjectsReq{
		Domain:      in.GetDomain(),
		SubjectType: in.GetSubjectType(),
		Subject:     in.GetSubject(),
		Relation:    in.GetRelation(),
		Permission:  in.GetPermission(),
		ObjectType:  in.GetObjectType(),
		Object:      in.GetObject(),
	})
	if err != nil {
		return &magistrala.CountSubjectsRes{}, err
	}

	cp := res.(countSubjectsRes)
	return &magistrala.CountSubjectsRes{Count: cp.count}, err
}

func decodeCountSubjectsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.CountSubjectsRes)
	return countSubjectsRes{count: res.GetCount()}, nil
}

func encodeCountSubjectsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(countSubjectsReq)
	return &magistrala.CountSubjectsReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		Subject:     req.Subject,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		Object:      req.Object,
	}, nil
}

func (client policyGrpcClient) ListPermissions(ctx context.Context, in *magistrala.ListPermissionsReq, opts ...grpc.CallOption) (*magistrala.ListPermissionsRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.listPermissions(ctx, listPermissionsReq{
		Domain:            in.GetDomain(),
		SubjectType:       in.GetSubjectType(),
		Subject:           in.GetSubject(),
		SubjectRelation:   in.GetSubjectRelation(),
		ObjectType:        in.GetObjectType(),
		Object:            in.GetObject(),
		FilterPermissions: in.GetFilterPermissions(),
	})
	if err != nil {
		return &magistrala.ListPermissionsRes{}, decodeError(err)
	}

	lp := res.(listPermissionsRes)
	return &magistrala.ListPermissionsRes{
		Domain:          lp.Domain,
		SubjectType:     lp.SubjectType,
		Subject:         lp.Subject,
		SubjectRelation: lp.SubjectRelation,
		ObjectType:      lp.ObjectType,
		Object:          lp.Object,
		Permissions:     lp.Permissions,
	}, nil
}

func decodeListPermissionsResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.ListPermissionsRes)
	return listPermissionsRes{
		Domain:          res.GetDomain(),
		SubjectType:     res.GetSubjectType(),
		Subject:         res.GetSubject(),
		SubjectRelation: res.GetSubjectRelation(),
		ObjectType:      res.GetObjectType(),
		Object:          res.GetObject(),
		Permissions:     res.GetPermissions(),
	}, nil
}

func encodeListPermissionsRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(listPermissionsReq)
	return &magistrala.ListPermissionsReq{
		Domain:            req.Domain,
		SubjectType:       req.SubjectType,
		Subject:           req.Subject,
		ObjectType:        req.ObjectType,
		Object:            req.Object,
		FilterPermissions: req.FilterPermissions,
	}, nil
}

func (client policyGrpcClient) DeleteEntityPolicies(ctx context.Context, in *magistrala.DeleteEntityPoliciesReq, opts ...grpc.CallOption) (*magistrala.DeletePolicyRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.deleteEntityPolicies(ctx, deleteEntityPoliciesReq{
		EntityType: in.GetEntityType(),
		ID:         in.GetId(),
	})
	if err != nil {
		return &magistrala.DeletePolicyRes{}, decodeError(err)
	}

	dpr := res.(deletePolicyRes)
	return &magistrala.DeletePolicyRes{Deleted: dpr.deleted}, nil
}

func decodeDeleteEntityPoliciesResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.DeletePolicyRes)
	return deletePolicyRes{deleted: res.GetDeleted()}, nil
}

func encodeDeleteEntityPoliciesRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(deleteEntityPoliciesReq)
	return &magistrala.DeleteEntityPoliciesReq{
		EntityType: req.EntityType,
		Id:         req.ID,
	}, nil
}

func decodeError(err error) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return errors.Wrap(svcerr.ErrNotFound, errors.New(st.Message()))
		case codes.InvalidArgument:
			return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
		case codes.AlreadyExists:
			return errors.Wrap(svcerr.ErrConflict, errors.New(st.Message()))
		case codes.Unauthenticated:
			return errors.Wrap(svcerr.ErrAuthentication, errors.New(st.Message()))
		case codes.OK:
			if msg := st.Message(); msg != "" {
				return errors.Wrap(errors.ErrUnidentified, errors.New(msg))
			}
			return nil
		case codes.FailedPrecondition:
			return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
		case codes.PermissionDenied:
			return errors.Wrap(svcerr.ErrAuthorization, errors.New(st.Message()))
		default:
			return errors.Wrap(fmt.Errorf("unexpected gRPC status: %s (status code:%v)", st.Code().String(), st.Code()), errors.New(st.Message()))
		}
	}
	return err
}
