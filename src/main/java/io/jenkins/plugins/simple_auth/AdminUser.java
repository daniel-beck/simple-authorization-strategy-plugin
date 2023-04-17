package io.jenkins.plugins.simple_auth;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import java.util.Locale;
import java.util.Objects;
import org.acegisecurity.acls.sid.PrincipalSid;
import org.acegisecurity.acls.sid.Sid;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;

@Restricted(NoExternalUse.class)
public class AdminUser extends AdminIdentity {

    private final String id;

    @DataBoundConstructor
    public AdminUser(String id) {
        this.id = id == null ? null : id.trim();
    }

    // Jelly
    public String getId() {
        return id;
    }

    @Override
    public Sid toSid() {
        return new PrincipalSid(id);
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AdminIdentity> {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.AdminUser_DisplayName();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AdminUser adminUser = (AdminUser) o;
        return Objects.equals(id, adminUser.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
