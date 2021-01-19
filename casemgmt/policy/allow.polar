# ALLOW RULES --- entrypoint for all authorization decisions

## Defer to models

### check for RBAC rule
allow(actor, action: String, resource) if
    rbac_allow(actor, action, resource);

### check for global rule
# allow(actor, action: String, resource) if
#     global_allow(actor, action, resource);

## Delegate by resource

### Delegate 

allow(user: casemgmt::User, action, case_type: casemgmt::CaseType) if
    caseload in case_type.caseloads and
    caseload matches casemgmt::Caseload and
    allow(user, action, caseload);

allow(user: casemgmt::User, action, template: casemgmt::DocumentTemplate) if
    case_type = template.case_type and
    case_type matches casemgmt::CaseType and
    allow(user, action, case_type);


allow(user: casemgmt::User, action, document: casemgmt::Document) if
    caseload in document.template.case_type.caseloads and
    caseload in document.client.caseloads and
    caseload matches casemgmt::Caseload and
    rbac_allow(user, action, caseload);