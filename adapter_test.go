package casbun_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/util"
	"github.com/mmikalsen/casbun"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
)

var modelStr = `
    [request_definition]
    r = sub, obj, act

    [policy_definition]
    p = sub, obj, act

    [role_definition]
    g = _, _

    [policy_effect]
    e = some(where (p.eft == allow))

    [matchers]
    m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func initDB() *bun.DB {
	sqldb, err := sql.Open(sqliteshim.ShimName, "file::memory:?mode=memory")
	if err != nil {
		panic(err)
	}
	db := bun.NewDB(sqldb, sqlitedialect.New())
	return db
}

func ensureHasPolicy(t *testing.T, db *bun.DB, e *casbin.Enforcer, want [][]string) {
	t.Helper()

	got, err := e.GetPolicy()
	if err != nil {
		t.Fatalf("unable to get policy: %v", err)
	}

	if !util.Array2DEquals(want, got) {
		t.Errorf("got %v, want %v", got, want)
	}

	var policies []casbun.CasbinPolicy
	count, err := db.NewSelect().Model(&policies).Where("ptype = 'p'").Count(context.Background())
	if err != nil {
		t.Fatalf("unable to get models from database: %v", err)
	}

	if count != len(got) {
		t.Errorf("inconsistent number of policies")
	}
}

func TestLoadPolicy(t *testing.T) {
	db := initDB()
	policies := []casbun.CasbinPolicy{
		{
			ID:    1,
			PType: "p",
			V0:    "alice",
			V1:    "data1",
			V2:    "read",
		},
		{
			ID:    2,
			PType: "p",
			V0:    "bob",
			V1:    "data1",
			V2:    "write",
		},
		{
			ID:    3,
			PType: "p",
			V0:    "admin",
			V1:    "*",
			V2:    "*",
		},
		{
			ID:    4,
			PType: "g",
			V0:    "bob",
			V1:    "admin",
		},
	}

	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{})

	if _, err := db.NewInsert().Model(&policies).Exec(context.Background()); err != nil {
		t.Fatalf("unable to insert policies into database: %v", err)
	}

	if err := e.LoadPolicy(); err != nil {
		t.Fatalf("unable to load policy: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{
		{"alice", "data1", "read"},
		{"bob", "data1", "write"},
		{"admin", "*", "*"},
	})
}

func TestSavePolicy(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	e.EnableAutoSave(false)

	if _, err := e.AddPolicy("alice", "data", "write"); err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}

	if err := e.SavePolicy(); err != nil {
		t.Errorf("unable to save policy: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{{"alice", "data", "write"}})
}

func TestAddPolicy(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	if _, err := e.AddPolicy("alice", "data", "write"); err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{{"alice", "data", "write"}})
}

func TestAddPolicies(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "write"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}

	ensureHasPolicy(t, db, e, policies)
}

func TestRemovePolicy(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "write"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}

	if ok, err := e.RemovePolicy("alice", "data2", "write"); !ok || err != nil {
		t.Fatalf("unable to remove policy: %v", err)
	}

	policies = policies[0:2]
	ensureHasPolicy(t, db, e, policies)
}

func TestRemovePolicies(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "write"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}
	ensureHasPolicy(t, db, e, policies)

	if ok, err := e.RemovePolicies(policies[1:3]); !ok || err != nil {
		t.Fatalf("unable to remove policy: %v", err)
	}

	policies = policies[:1]
	ensureHasPolicy(t, db, e, policies)
}

func TestRemoveFilteredPolicy(t *testing.T) {
	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}

	ok, err := e.RemoveFilteredPolicy(
		0,
		"alice",
	)
	if err != nil || !ok {
		t.Fatalf("unable to update filtered policies: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{
		{"bob", "data1", "read"},
	})
}

func TestUpdatePolicy(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "write"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}
	ensureHasPolicy(t, db, e, policies)

	newPolicy := []string{"alice", "data1", "read"}
	ok, err := e.UpdatePolicy(policies[0], newPolicy)
	if !ok || err != nil {
		t.Fatalf("unable to update policy: %v", err)
	}

	policies[0] = newPolicy
	ensureHasPolicy(t, db, e, policies)
}

func TestUpdatePolicies(t *testing.T) {
	t.Parallel()

	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "write"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}
	ensureHasPolicy(t, db, e, policies)

	newPolicies := [][]string{
		{"alice", "data1", "read"},
		{"alice", "data2", "read"},
	}

	old := [][]string{policies[0], policies[2]}
	ok, err := e.UpdatePolicies(old, newPolicies)
	if !ok || err != nil {
		t.Fatalf("unable to update policy: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{newPolicies[0], policies[1], newPolicies[1]})
}

func TestUpdateFilteredPolicies(t *testing.T) {
	db := initDB()
	adapter, err := casbun.NewAdapter(context.Background(), db)
	if err != nil {
		t.Fatalf("unable to create adapter: %v", err)
	}

	m, _ := model.NewModelFromString(modelStr)
	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		t.Fatalf("failed to create enforcer: %v", err)
	}

	policies := [][]string{
		{"alice", "data1", "read"},
		{"bob", "data1", "read"},
		{"alice", "data2", "write"},
	}

	if _, err := e.AddPolicies(policies); err != nil {
		t.Fatalf("failed to add policies: %v", err)
	}

	ok, err := e.UpdateFilteredPolicies(
		[][]string{{"alice", "data1", "write"}, {"bob", "data1", "write"}},
		1,
		"data1",
		"read",
	)
	if err != nil || !ok {
		t.Fatalf("unable to update filtered policies: %v", err)
	}

	ensureHasPolicy(t, db, e, [][]string{
		{"alice", "data2", "write"},
		{"alice", "data1", "write"},
		{"bob", "data1", "write"},
	})
}
