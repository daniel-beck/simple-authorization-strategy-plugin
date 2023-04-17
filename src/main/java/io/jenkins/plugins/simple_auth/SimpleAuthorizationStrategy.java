package io.jenkins.plugins.simple_auth;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.AuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionAdder;
import hudson.security.SparseACL;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;

@Restricted(NoExternalUse.class)
public class SimpleAuthorizationStrategy extends AuthorizationStrategy {

    private final boolean anonymousReadAccess;
    private final Set<AdminIdentity> adminIdentities = new LinkedHashSet<>();

    private transient SparseACL acl;

    @DataBoundConstructor
    public SimpleAuthorizationStrategy(boolean anonymousReadAccess, List<AdminIdentity> adminIdentities) {
        this.anonymousReadAccess = anonymousReadAccess;

        if (adminIdentities != null) {
            this.adminIdentities.addAll(adminIdentities);
        }
        if (this.adminIdentities.isEmpty()) {
            if (!Jenkins.getAuthentication2().equals(ACL.SYSTEM2)) {
                // Try to ensure that, in case of no defined admins, we add the current user
                // Lockout conditions that still exist:
                // - Admins defined only for a non-existent user or group, then
                // - Local user DB exists, current user is anonymous, newly selecting this security realm (no "Create First Admin User")
                final User current = User.current();
                if (current != null) {
                    this.adminIdentities.add(new AdminUser(current.getId()));
                }
            }
        }
    }

    // Jelly
    public List<AdminIdentity> getAdminIdentities() {
        return new ArrayList<>(adminIdentities);
    }

    // Jelly
    public boolean isAnonymousReadAccess() {
        return anonymousReadAccess;
    }

    @NonNull
    @Override
    public synchronized ACL getRootACL() {
        if (acl == null) {
            this.acl = new SparseACL(null);

            // Grant all logged-in users (and possibly anonymous) Read access
            this.acl.add(ACL.EVERYONE, Permission.READ, true);
            if (!anonymousReadAccess) {
                this.acl.add(ACL.ANONYMOUS, Permission.READ, false);
            }

            // admin permissions
            this.adminIdentities.forEach(identity -> this.acl.add(identity.toSid(), Jenkins.ADMINISTER, true));
        }
        return acl;
    }

    private void addUser(AdminUser adminUser) {
        this.adminIdentities.add(adminUser);
        reset();
    }

    private synchronized void reset() {
        this.acl = null;
    }

    @NonNull
    @Override
    public Collection<String> getGroups() {
        return Collections.emptyList();
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AuthorizationStrategy> {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.SimpleAuthorizationStrategy_DisplayName();
        }

        @Restricted(NoExternalUse.class) // Jelly
        public List<AdminUser.DescriptorImpl> getAdminIdentityDescriptors() {
            return Jenkins.get().getDescriptorList(AdminIdentity.class);
        }
    }

    @Extension
    public static class PermissionAdderImpl extends PermissionAdder {
        @Override
        public boolean add(AuthorizationStrategy strategy, hudson.model.User user, Permission perm) {
            if (strategy instanceof SimpleAuthorizationStrategy) {
                if (Jenkins.ADMINISTER.equals(perm)) {
                    final String id = user.getId();
                    ((SimpleAuthorizationStrategy) strategy).addUser(new AdminUser(id));
                    try {
                        Jenkins.get().save();
                    } catch (IOException e) {
                        Logger.getLogger(PermissionAdderImpl.class.getName()).log(Level.WARNING, "Failed to save Jenkins to persist permissions added for " + id, e);
                    }
                    return true;
                }
            }
            return false;
        }
    }
}
