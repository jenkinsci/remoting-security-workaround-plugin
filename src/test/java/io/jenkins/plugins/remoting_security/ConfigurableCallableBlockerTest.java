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
import hudson.FilePath;
import hudson.Functions;
import hudson.slaves.SlaveComputer;
import jenkins.security.MasterToSlaveCallable;
import jenkins.security.SlaveToMasterCallable;
import jenkins.security.s2m.AdminWhitelistRule;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import java.io.File;
import java.util.Objects;
import java.util.logging.Level;

import static io.jenkins.plugins.remoting_security.TestUtil.assertThrowsIOExceptionCausedBySecurityException;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ConfigurableCallableBlockerTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule().record("io.jenkins.plugins.remoting_security", Level.INFO).capture(100);

    /**
     * Agent-writable directory (based on filepaths allowlist)
     */
    private File buildDir;

    @Before
    public void enableAgentToControllerProtections() throws Exception {
        AdminWhitelistRule rule = ExtensionList.lookupSingleton(AdminWhitelistRule.class);
        rule.setMasterKillSwitch(false);
        buildDir = j.buildAndAssertSuccess(j.createFreeStyleProject()).getRootDir();
    }

    @Test
    public void testDefaultFileCallableWrapperBlock() {
        assertThrowsIOExceptionCausedBySecurityException(() -> Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new DefaultFileCallableWrapperBlockCallable(buildDir.getAbsolutePath())));
        assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("of type class hudson.FilePath$FileCallableWrapper regardless of role checker")));
    }

    @Test
    public void testAllowFileCallableWrapper() throws Exception {
        Assume.assumeFalse(Functions.isWindows());
        final String className = "hudson.FilePath$FileCallableWrapper";
        ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.remove(className);
        try {
            Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new DefaultFileCallableWrapperBlockCallable(buildDir.getAbsolutePath()));
            assertFalse(l.getMessages().stream().anyMatch(m -> m.contains("of type class hudson.FilePath$FileCallableWrapper regardless of role checker")));
        } finally {
            ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add(className);
        }
    }

    @Test
    public void testCustomBlockList() throws Exception {
        final String className = "hudson.FilePath$FileCallableWrapper";
        ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.remove(className);
        try {
            Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new DefaultFileCallableWrapperBlockCallable(buildDir.getAbsolutePath()));
            assertFalse(l.getMessages().stream().anyMatch(m -> m.contains("of type class hudson.FilePath$FileCallableWrapper regardless of role checker")));
        } finally {
            ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add(className);
        }
    }

    @Test
    public void testAddToBlockList() throws Exception {
        final String className = InnocentCallable.class.getName();

        Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new InnocentCallableCaller());
        assertFalse(l.getMessages().stream().anyMatch(m -> m.contains("of type class " + className + " regardless of role checker")));

        ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add(className);
        try {
            assertThrowsIOExceptionCausedBySecurityException(() -> Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new InnocentCallableCaller()));
            assertTrue(l.getMessages().stream().anyMatch(m -> m.contains("of type class " + className + " regardless of role checker")));
        } finally {
            ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.remove(className);
        }
    }

    private static class DefaultFileCallableWrapperBlockCallable extends MasterToSlaveCallable<Object, Exception> {
        private final String buildDir;

        DefaultFileCallableWrapperBlockCallable(String buildDir) {
            this.buildDir = buildDir;
        }
        @Override
        public Object call() throws Exception {
            FilePath fp = new FilePath(SlaveComputer.getChannelToMaster(), buildDir + "/remoting-workaround-test");
            fp.mkdirs();
            return null;
        }
    }

    private static class InnocentCallableCaller extends MasterToSlaveCallable<Object, Exception> {
        @Override
        public Object call() throws Exception {
            return SlaveComputer.getChannelToMaster().call(new InnocentCallable());
        }
    }
    private static class InnocentCallable extends SlaveToMasterCallable<Object, Exception> {
        @Override
        public Object call() throws Exception {
            return null;
        }
    }
}
