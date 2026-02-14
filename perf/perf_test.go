package perf

import (
	"testing"

	"github.com/brian-nunez/baccess"
)

type MockUser struct {
	ID         string
	Roles      []string
	Department string
}

func (u MockUser) GetID() string {
	return u.ID
}

func (u MockUser) GetRoles() []string {
	return u.Roles
}

func (u MockUser) GetAttribute(key string) any {
	switch key {
	case "department":
		return u.Department
	default:
		return nil
	}
}

type MockDocument struct {
	OwnerID       string
	Collaborators []string
	Status        string
}

func (d MockDocument) GetOwnerID() string {
	return d.OwnerID
}

func (d MockDocument) GetAttribute(key string) any {
	switch key {
	case "status":
		return d.Status
	default:
		return nil
	}
}

func BenchmarkPolicyEvaluation(b *testing.B) {
	rbac := baccess.NewRBAC[MockUser, MockDocument]()
	registry := baccess.NewRegistry[MockUser, MockDocument]()

	isOwnerPred := baccess.FieldEquals(
		func(u MockUser) string { return u.ID },
		func(d MockDocument) string { return d.OwnerID },
	)
	registry.Register("isOwner", isOwnerPred)

	isCollaboratorPred := baccess.SubjectInResourceList(
		func(u MockUser) string { return u.ID },
		func(d MockDocument) []string { return d.Collaborators },
	)
	registry.Register("isCollaborator", isCollaboratorPred)

	isDepartmentMemberPred := baccess.FieldEquals(
		func(u MockUser) string { return u.Department },
		func(d MockDocument) string {
			return "Engineering"
		},
	)
	registry.Register("isDepartmentMember", isDepartmentMemberPred)

	docStatusIsDraftPred := baccess.ResourceMatches[MockUser](
		func(d MockDocument) string { return d.Status },
		"draft",
	)
	registry.Register("docStatusIsDraft", docStatusIsDraftPred)

	notOwnerPred := baccess.Not(isOwnerPred)
	registry.Register("isNotOwner", notOwnerPred)

	canUpdatePred := isOwnerPred.Or(isCollaboratorPred)
	registry.Register("canUpdate", canUpdatePred)

	canPublishPred := isOwnerPred.And(docStatusIsDraftPred)
	registry.Register("canPublish", canPublishPred)

	cfg := &baccess.Config{
		Policies: map[string]baccess.RolePolicyConfig{
			"admin": {
				Allow: []string{"*"},
			},
			"editor": {
				Allow: []string{
					"read:*",
					"delete:isOwner",
					"update:canUpdate",
					"archive:isNotOwner",
					"publish:canPublish",
				},
			},
			"contributor": {
				Allow: []string{
					"comment:isDepartmentMember",
				},
			},
		},
	}

	evaluator, err := baccess.BuildEvaluator(cfg, rbac, registry)
	if err != nil {
		b.Fatalf("Failed to build evaluator: %v", err)
	}

	adminUser := MockUser{ID: "admin1", Roles: []string{"admin"}, Department: "IT"}
	editorUser := MockUser{ID: "editor1", Roles: []string{"editor"}, Department: "Engineering"}
	contributorUser := MockUser{ID: "contrib1", Roles: []string{"contributor"}, Department: "Engineering"}
	otherUser := MockUser{ID: "other1", Roles: []string{"viewer"}, Department: "Sales"}

	ownedDoc := MockDocument{OwnerID: "editor1", Collaborators: []string{"collab1"}, Status: "draft"}
	collabDoc := MockDocument{OwnerID: "other1", Collaborators: []string{"editor1", "collab2"}, Status: "published"}
	alienDoc := MockDocument{OwnerID: "alien1", Collaborators: []string{"collab1"}, Status: "draft"}
	publishedOwnedDoc := MockDocument{OwnerID: "editor1", Collaborators: []string{"collab1"}, Status: "published"}

	b.ResetTimer()

	b.Run("ReadAccess_SimpleAllow", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: ownedDoc, Action: "read"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("DeleteAccess_Owner_True", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: ownedDoc, Action: "delete"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("DeleteAccess_Owner_False", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: alienDoc, Action: "delete"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("UpdateAccess_OwnerOrCollaborator_OwnerTrue", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: ownedDoc, Action: "update"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("UpdateAccess_OwnerOrCollaborator_CollaboratorTrue", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: collabDoc, Action: "update"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("UpdateAccess_OwnerOrCollaborator_False", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: otherUser, Resource: ownedDoc, Action: "update"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("ArchiveAccess_NotOwner_True", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: alienDoc, Action: "archive"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("ArchiveAccess_NotOwner_False", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: ownedDoc, Action: "archive"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("PublishAccess_OwnerAndDraft_True", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: ownedDoc, Action: "publish"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("PublishAccess_OwnerAndDraft_False_NotOwner", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: contributorUser, Resource: ownedDoc, Action: "publish"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("PublishAccess_OwnerAndDraft_False_NotDraft", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: editorUser, Resource: publishedOwnedDoc, Action: "publish"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("CommentAccess_DepartmentMember_True", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: contributorUser, Resource: ownedDoc, Action: "comment"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("CommentAccess_DepartmentMember_False", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: otherUser, Resource: ownedDoc, Action: "comment"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})

	b.Run("AdminAccess_WildcardAction", func(b *testing.B) {
		req := baccess.AccessRequest[MockUser, MockDocument]{Subject: adminUser, Resource: alienDoc, Action: "anything"}
		for b.Loop() {
			evaluator.Evaluate(req)
		}
	})
}
