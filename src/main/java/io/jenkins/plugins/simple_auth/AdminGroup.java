package io.jenkins.plugins.simple_auth;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Descriptor;
import java.util.Objects;
import org.acegisecurity.acls.sid.GrantedAuthoritySid;
import org.acegisecurity.acls.sid.Sid;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;

@Restricted(NoExternalUse.class)
public class AdminGroup extends AdminIdentity {

    private final String name;

    @DataBoundConstructor
    public AdminGroup(String name) {
        this.name = name == null ? null : name.trim();
    }

    public String getName() {
        return name;
    }

    @Override
    public Sid toSid() {
        return new GrantedAuthoritySid(name);
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<AdminIdentity> {
        @NonNull
        @Override
        public String getDisplayName() {
            return Messages.AdminGroup_DisplayName();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AdminGroup that = (AdminGroup) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }
}
