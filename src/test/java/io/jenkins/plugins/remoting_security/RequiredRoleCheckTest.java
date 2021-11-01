/*
 * The MIT License
 *
 * Copyright (c) 2021, CloudBees, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.jenkins.plugins.remoting_security;

import hudson.ExtensionList;
import hudson.remoting.Callable;
import hudson.slaves.SlaveComputer;
import jenkins.security.MasterToSlaveCallable;
import jenkins.security.s2m.AdminWhitelistRule;
import org.jenkinsci.remoting.RoleChecker;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Objects;

import static io.jenkins.plugins.remoting_security.TestUtil.assertThrowsIOExceptionCausedBySecurityException;

public class RequiredRoleCheckTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Before
    public void enableAgentToControllerProtections() {
        AdminWhitelistRule rule = ExtensionList.lookupSingleton(AdminWhitelistRule.class);
        rule.setMasterKillSwitch(false);
    }

    @Test
    public void testRequiredRoleCheck() {
        assertThrowsIOExceptionCausedBySecurityException(() -> Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new RequiredRoleCheckCallable()));
    }

    private static class RequiredRoleCheckCallable extends MasterToSlaveCallable<Object, Throwable> {
        @Override
        public Object call() throws Throwable {
            return SlaveComputer.getChannelToMaster().call(new NonRoleCheckingCallable());
        }
    }

    private static class NonRoleCheckingCallable implements Callable<Object, Throwable> {
        @Override
        public Object call() throws Throwable {
            return null;
        }

        @Override
        public void checkRoles(RoleChecker roleChecker) throws SecurityException {
            // This method intentionally left blank.
        }
    }
}
