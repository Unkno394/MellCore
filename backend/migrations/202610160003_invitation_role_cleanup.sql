ALTER TABLE user_invitation_roles
    DROP CONSTRAINT user_invitation_roles_role_id_fkey;
ALTER TABLE user_invitation_roles
    ADD CONSTRAINT user_invitation_roles_role_id_fkey
    FOREIGN KEY(role_id) REFERENCES rbac_roles(id) ON DELETE CASCADE;
