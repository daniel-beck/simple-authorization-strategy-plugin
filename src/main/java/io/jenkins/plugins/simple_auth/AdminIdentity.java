package io.jenkins.plugins.simple_auth;

import hudson.model.AbstractDescribableImpl;
import org.acegisecurity.acls.sid.Sid;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class)
public abstract class AdminIdentity extends AbstractDescribableImpl<AdminIdentity> {
    public abstract Sid toSid();
}
