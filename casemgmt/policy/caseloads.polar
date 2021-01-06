## Model-specific rules for caseload roles.
## (Would be autogenerated by oso)

user_in_role(user: casemgmt::User, role, resource: casemgmt::Caseload) if
    ## Note: we are using the related name to go from resource to the m2m model
    ## This should be preferred so all attributes at written over the resource partial
    caseload_role in resource.caseload_roles and
    caseload_role.user = user and
    role = caseload_role.role;

### Maps action to `casemgmt.{action}_caseload`
### e.g. "view" -> "casemgmt.view_caseload"
action_to_permission(action, _: casemgmt::Caseload, perm) if
    perm = "_".join([action, "caseload"]);

# Direct role permission assignments
role_allow(role, action, resource) if
    action_to_permission(action, resource, permission) and
    role_perm in role.permissions and
    role_perm.codename = permission and
    role_perm.content_type.app_label = "casemgmt" and
    role_perm.content_type.model = "caseload";

# TODO: Revisit
# inherits_role(role: CaseloadRole, inherited_role) if
#     caseload_role_order(role_order) and
#     inherits_role_helper(role.name, inherited_role_name, role_order) and
#     inherited_role = new CaseloadRole(name: inherited_role_name, caseload: role.caseload);
