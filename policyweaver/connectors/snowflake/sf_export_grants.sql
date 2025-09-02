-- The data returned by both queries is in the
-- SNOWFLAKE database, which has latency of up
-- to 3 hours to reflect changes
 
-- Get the effective role hierarchy for each user.
with
   -- CTE gets all the roles each role is granted
   ROLE_MEMBERSHIPS(ROLE_GRANTEE, ROLE_GRANTED_THROUGH_ROLE)
   as
    (
    select   GRANTEE_NAME, "NAME"
    from     SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
    where    GRANTED_TO = 'ROLE' and
             GRANTED_ON = 'ROLE' and
             DELETED_ON is null
    ),
    -- CTE gets all roles a user is granted
    USER_MEMBERSHIPS(ROLE_GRANTED_TO_USER, USER_GRANTEE, GRANTED_BY)
    as
     (
     select ROLE,
            GRANTEE_NAME,
            GRANTED_BY
     from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
     where DELETED_ON is null
     )
-- 
select
        USER_GRANTEE,
        case
            when ROLE_GRANTED_THROUGH_ROLE is null
                then ROLE_GRANTED_TO_USER 
            else ROLE_GRANTED_THROUGH_ROLE
        end
        EFFECTIVE_ROLE,
        GRANTED_BY,
        ROLE_GRANTEE,
        ROLE_GRANTED_TO_USER,
        ROLE_GRANTED_THROUGH_ROLE
from    USER_MEMBERSHIPS U
    left join ROLE_MEMBERSHIPS R
        on U.ROLE_GRANTED_TO_USER = R.ROLE_GRANTEE
;
 
--------------------------------------------------------------------------------------------------
 
-- This gets all the grants for all of the users:
with
    ROLE_MEMBERSHIPS
        (
            ROLE_GRANTEE, 
            ROLE_GRANTED_THROUGH_ROLE
        )
    as
    (
        -- This lists all the roles a role is in
        select   GRANTEE_NAME, "NAME"
        from     SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        where    GRANTED_TO = 'ROLE' and
                 GRANTED_ON = 'ROLE' and
                 DELETED_ON is null
    ),
    USER_MEMBERSHIPS
        (
            ROLE_GRANTED_TO_USER,
            USER_GRANTEE,
            GRANTED_BY
        )
    as
     (
        select ROLE,GRANTEE_NAME,GRANTED_BY
        from SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
        where DELETED_ON is null
     ),
    EFFECTIVE_ROLES
    (
        USER_GRANTEE,
        EFFECTIVE_ROLE,
        GRANTED_BY,
        ROLE_GRANTEE,
        ROLE_GRANTED_TO_USER,
        ROLE_GRANTED_THROUGH_ROLE
    )
    as
    (
        select
            USER_GRANTEE,
            case
                when ROLE_GRANTED_THROUGH_ROLE is null
                    then ROLE_GRANTED_TO_USER
                else ROLE_GRANTED_THROUGH_ROLE
            end
            EFFECTIVE_ROLE,
            GRANTED_BY,
            ROLE_GRANTEE,
            ROLE_GRANTED_TO_USER,
            ROLE_GRANTED_THROUGH_ROLE
        from USER_MEMBERSHIPS U
            left join ROLE_MEMBERSHIPS R
            on U.ROLE_GRANTED_TO_USER = R.ROLE_GRANTEE
    ),
    GRANT_LIST
        (
            CREATED_ON,
            MODIFIED_ON,
            PRIVILEGE,
            GRANTED_ON, 
            "NAME",
            TABLE_CATALOG,
            TABLE_SCHEMA,
            GRANTED_TO,
            GRANTEE_NAME,
            GRANT_OPTION
        )
    as
    (
        -- This shows all the grants (other than to roles)
        select  CREATED_ON,
                MODIFIED_ON,
                PRIVILEGE,
                "NAME",
                TABLE_CATALOG,
                TABLE_SCHEMA,
                GRANTED_TO,
                GRANTEE_NAME,
                GRANT_OPTION,
                GRANTED_ON
        from    SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
        where   GRANTED_ON <> 'ROLE' and
                PRIVILEGE <> 'USAGE' and
                DELETED_ON is null
    )
select * from EFFECTIVE_ROLES R
    left join GRANT_LIST G 
        on G.GRANTED_TO = R.EFFECTIVE_ROLE
where G.PRIVILEGE is not null
;
