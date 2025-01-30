package casbun

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/uptrace/bun"
)

var (
	_ persist.Adapter                 = (*Adapter)(nil)
	_ persist.BatchAdapter            = (*Adapter)(nil)
	_ persist.UpdatableAdapter        = (*Adapter)(nil)
	_ persist.ContextAdapter          = (*Adapter)(nil)
	_ persist.ContextBatchAdapter     = (*Adapter)(nil)
	_ persist.ContextUpdatableAdapter = (*Adapter)(nil)
)

// Adapter represents the Bun adapter for policy storage.
type Adapter struct {
	db              *bun.DB
	notCreateTables bool
}

// CasbinBunOption defines a functional option type for configuring a BunAdapter.
// These options are passed to NewAdapter to customize the adapter's behavior.
type CasbinBunOption func(*Adapter)

// DisableAutoCreateTable disables automatic creation of the Casbin policy storage table
// during adapter initialization.
// If used, the policy table must already exist in the database.
//
// Example:
//
//	adapter, err := NewAdapter(db, DisableAutoCreateTable())
func DisableAutoCreateTable() CasbinBunOption {
	return func(a *Adapter) {
		a.notCreateTables = true
	}
}

// NewAdapter creates a new Casbin policy adapter using a Bun database connection.
//
// Example:
//
//	db := bun.NewDB(sqlDB, pgdialect.New())
//	adapter, err := NewAdapter(ctx, db, WithAutoCreateTable())
//	if err != nil {
//	    log.Fatal("Failed to create adapter:", err)
//	}
//	enforcer, err := casbin.NewEnforcer("model.conf", adapter)
func NewAdapter(ctx context.Context, db *bun.DB, opts ...CasbinBunOption) (*Adapter, error) {
	b := &Adapter{
		db: db,
	}

	for _, opt := range opts {
		opt(b)
	}

	if !b.notCreateTables {
		if err := b.createTable(ctx); err != nil {
			return nil, err
		}
	}

	runtime.SetFinalizer(b, func(a *Adapter) {
		if err := a.db.Close(); err != nil {
			panic(err)
		}
	})

	return b, nil
}

func (a *Adapter) createTable(ctx context.Context) error {
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	if _, err := tx.NewCreateTable().
		Model((*CasbinPolicy)(nil)).
		IfNotExists().
		Exec(ctx); err != nil {
		return errors.Join(err, tx.Rollback())
	}

	if _, err := tx.NewRaw(
		"CREATE UNIQUE INDEX unique_casbin_policy on casbin_policies (ptype, v0, v1, v2, v3, v4, v5)",
	).Exec(ctx); err != nil {
		return errors.Join(err, tx.Rollback())
	}

	if _, err := tx.NewRaw("CREATE INDEX idx_casbin_ptype ON casbin_policies (ptype)").Exec(ctx); err != nil {
		return errors.Join(err, tx.Rollback())
	}

	return tx.Commit()
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadPolicyCtx(context.Background(), model)
}

// LoadPolicyCtx loads all policy rules from the storage with context.
func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	var policies []CasbinPolicy
	err := a.db.NewSelect().
		Model(&policies).
		Scan(ctx)
	if err != nil {
		return err
	}

	for _, policy := range policies {
		if err := loadPolicyRecord(policy, model); err != nil {
			return err
		}
	}

	return nil
}

func loadPolicyRecord(policy CasbinPolicy, model model.Model) error {
	pType := policy.PType
	sec := pType[:1]
	ok, err := model.HasPolicyEx(sec, pType, policy.filterValues())
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return model.AddPolicy(sec, pType, policy.filterValues())
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx saves all policy rules to the storage with context.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	policies := make([]CasbinPolicy, 0, len(model["p"])+len(model["g"]))

	// go through policy definitions
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			policies = append(policies, newCasbinPolicy(ptype, rule))
		}
	}

	// go through role definitions
	for gtype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			policies = append(policies, newCasbinPolicy(gtype, rule))
		}
	}

	return a.savePolicyRecords(ctx, policies)
}

func (a *Adapter) savePolicyRecords(ctx context.Context, policies []CasbinPolicy) error {
	if err := a.refreshTable(ctx); err != nil {
		return err
	}

	if _, err := a.db.NewInsert().
		Model(&policies).
		Exec(ctx); err != nil {
		return err
	}

	return nil
}

// refreshTable truncates the table.
func (a *Adapter) refreshTable(ctx context.Context) error {
	if _, err := a.db.NewTruncateTable().
		Model((*CasbinPolicy)(nil)).
		Exec(ctx); err != nil {
		return err
	}
	return nil
}

// AddPolicy adds a policy rule to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicyCtx adds a policy rule to the storage with context.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicyCtx(ctx context.Context, _, ptype string, rule []string) error {
	newPolicy := newCasbinPolicy(ptype, rule)
	if _, err := a.db.NewInsert().
		Model(&newPolicy).
		Exec(ctx); err != nil {
		return err
	}
	return nil
}

// AddPolicies adds policy rules to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicies(sec, ptype string, rules [][]string) error {
	return a.AddPoliciesCtx(context.Background(), sec, ptype, rules)
}

// AddPoliciesCtx adds policy rules to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPoliciesCtx(ctx context.Context, _, ptype string, rules [][]string) error {
	policies := make([]CasbinPolicy, 0, len(rules))
	for _, rule := range rules {
		policies = append(policies, newCasbinPolicy(ptype, rule))
	}
	if _, err := a.db.NewInsert().
		Model(&policies).
		Exec(ctx); err != nil {
		return err
	}
	return nil
}

// RemovePolicy removes a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicyCtx removes a policy rule from the storage with context.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, _, ptype string, rule []string) error {
	exisingPolicy := newCasbinPolicy(ptype, rule)
	if err := a.deleteRecord(ctx, exisingPolicy); err != nil {
		return err
	}
	return nil
}

// RemovePolicies removes policy rules from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicies(sec, ptype string, rules [][]string) error {
	return a.RemovePoliciesCtx(context.Background(), sec, ptype, rules)
}

// RemovePoliciesCtx removes policy rules from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePoliciesCtx(ctx context.Context, _, ptype string, rules [][]string) error {
	return a.db.RunInTx(
		ctx,
		&sql.TxOptions{},
		func(ctx context.Context, tx bun.Tx) error {
			for _, rule := range rules {
				exisingPolicy := newCasbinPolicy(ptype, rule)
				if err := a.deleteRecordInTx(ctx, tx, exisingPolicy); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

func (a *Adapter) deleteRecord(ctx context.Context, existingPolicy CasbinPolicy) error {
	query := a.db.NewDelete().
		Model((*CasbinPolicy)(nil)).
		Where("ptype = ?", existingPolicy.PType)

	values := existingPolicy.filterValuesWithKey()

	return a.delete(ctx, query, values)
}

func (a *Adapter) deleteRecordInTx(
	ctx context.Context,
	tx bun.Tx,
	existingPolicy CasbinPolicy,
) error {
	query := tx.NewDelete().
		Model((*CasbinPolicy)(nil)).
		Where("ptype = ?", existingPolicy.PType)

	values := existingPolicy.filterValuesWithKey()

	return a.delete(ctx, query, values)
}

func (a *Adapter) delete(
	ctx context.Context,
	query *bun.DeleteQuery,
	values map[string]string,
) error {
	for key, value := range values {
		query = query.Where(fmt.Sprintf("%s = ?", key), value)
	}

	if _, err := query.Exec(ctx); err != nil {
		return err
	}

	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is part of the Auto-Save feature.
// This API is explained in the link below:
// https://casbin.org/docs/management-api/#removefilteredpolicy
func (a *Adapter) RemoveFilteredPolicy(
	sec, ptype string,
	fieldIndex int,
	fieldValues ...string,
) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage with context.
// This is part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicyCtx(
	ctx context.Context,
	sec, ptype string,
	fieldIndex int,
	fieldValues ...string,
) error {
	return a.deleteFilteredPolicy(ctx, ptype, fieldIndex, fieldValues...)
}

func (a *Adapter) deleteFilteredPolicy(
	ctx context.Context,
	ptype string,
	fieldIndex int,
	fieldValues ...string,
) error {
	query := a.db.NewDelete().
		Model((*CasbinPolicy)(nil)).
		Where("ptype = ?", ptype)

	for n := 0; n <= 5; n++ {
		if fieldIndex > n || n >= fieldIndex+len(fieldValues) {
			continue
		}

		value := fieldValues[n-fieldIndex]
		col := fmt.Sprintf("v%d", n)

		if value == "" {
			query = query.Where(col + " LIKE '%'")
		} else {
			query = query.Where(col+" = ?", value)
		}
	}

	if _, err := query.Exec(ctx); err != nil {
		return err
	}

	return nil
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec, ptype string, oldRule, newRule []string) error {
	return a.UpdatePolicyCtx(context.Background(), sec, ptype, oldRule, newRule)
}

// UpdatePolicyCtx updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicyCtx(
	ctx context.Context,
	sec, ptype string,
	oldRule, newRule []string,
) error {
	oldPolicy := newCasbinPolicy(ptype, oldRule)
	newPolicy := newCasbinPolicy(ptype, newRule)
	return a.updateRecord(ctx, oldPolicy, newPolicy)
}

func (a *Adapter) updateRecord(ctx context.Context, oldPolicy, newPolicy CasbinPolicy) error {
	query := a.db.NewUpdate().
		Model(&newPolicy).
		Where("ptype = ?", oldPolicy.PType)

	values := oldPolicy.filterValuesWithKey()

	return a.update(ctx, query, values)
}

func (a *Adapter) updateRecordInTx(
	ctx context.Context,
	tx bun.Tx,
	oldPolicy, newPolicy CasbinPolicy,
) error {
	query := tx.NewUpdate().
		Model(&newPolicy).
		Where("ptype = ?", oldPolicy.PType)

	values := oldPolicy.filterValuesWithKey()

	return a.update(ctx, query, values)
}

func (a *Adapter) update(
	ctx context.Context,
	query *bun.UpdateQuery,
	values map[string]string,
) error {
	for key, value := range values {
		query = query.Where(fmt.Sprintf("%s = ?", key), value)
	}

	if _, err := query.Exec(ctx); err != nil {
		return err
	}

	return nil
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePolicies(sec, ptype string, oldRules, newRules [][]string) error {
	return a.UpdatePoliciesCtx(context.Background(), sec, ptype, oldRules, newRules)
}

// UpdatePoliciesCtx updates some policy rules to storage, like db, redis.
func (a *Adapter) UpdatePoliciesCtx(
	ctx context.Context,
	sec, ptype string,
	oldRules, newRules [][]string,
) error {
	oldPolicies := make([]CasbinPolicy, 0, len(oldRules))
	newPolicies := make([]CasbinPolicy, 0, len(newRules))
	for _, rule := range oldRules {
		oldPolicies = append(oldPolicies, newCasbinPolicy(ptype, rule))
	}
	for _, rule := range newRules {
		newPolicies = append(newPolicies, newCasbinPolicy(ptype, rule))
	}

	return a.db.RunInTx(
		ctx,
		&sql.TxOptions{},
		func(ctx context.Context, tx bun.Tx) error {
			for i := range oldPolicies {
				if err := a.updateRecordInTx(ctx, tx, oldPolicies[i], newPolicies[i]); err != nil {
					return err
				}
			}
			return nil
		},
	)
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(
	sec, ptype string,
	newRules [][]string,
	fieldIndex int,
	fieldValues ...string,
) ([][]string, error) {
	return a.UpdateFilteredPoliciesCtx(
		context.Background(),
		sec,
		ptype,
		newRules,
		fieldIndex,
		fieldValues...)
}

// UpdateFilteredPoliciesCtx deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPoliciesCtx(
	ctx context.Context,
	sec, ptype string,
	newRules [][]string,
	fieldIndex int,
	fieldValues ...string,
) ([][]string, error) {
	newPolicies := make([]CasbinPolicy, 0, len(newRules))
	for _, rule := range newRules {
		newPolicies = append(newPolicies, newCasbinPolicy(ptype, rule))
	}

	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, err
	}

	oldPolicies := make([]CasbinPolicy, 0)
	selectQuery := tx.NewSelect().
		Model(&oldPolicies).
		Where("ptype = ?", ptype)
	deleteQuery := tx.NewDelete().
		Model((*CasbinPolicy)(nil)).
		Where("ptype = ?", ptype)

	for n := 0; n <= 5; n++ {
		if fieldIndex > n || n >= fieldIndex+len(fieldValues) {
			continue
		}

		value := fieldValues[n-fieldIndex]
		col := fmt.Sprintf("v%d", n)
		condition := col + " LIKE '%'"
		if value != "" {
			condition = col + " = ?"
		}

		selectQuery = selectQuery.Where(condition, value)
		deleteQuery = deleteQuery.Where(condition, value)
	}

	if err := selectQuery.Scan(ctx); err != nil {
		if err := tx.Rollback(); err != nil {
			return nil, err
		}
		return nil, err
	}

	if _, err := deleteQuery.Exec(ctx); err != nil {
		if err := tx.Rollback(); err != nil {
			return nil, err
		}
		return nil, err
	}

	if _, err := tx.NewInsert().
		Model(&newPolicies).
		Exec(ctx); err != nil {
		if err := tx.Rollback(); err != nil {
			return nil, err
		}
		return nil, err
	}

	out := make([][]string, 0, len(oldPolicies))
	for _, policy := range oldPolicies {
		out = append(out, policy.toSlice())
	}

	return out, tx.Commit()
}
