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

import hudson.remoting.VirtualChannel;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Objects;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

@SuppressWarnings("ThrowableNotThrown")
public class TesterTest {
    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Test
    public void testDefault() throws Exception {
        Objects.requireNonNull(j.createOnlineSlave().getChannel()).call(new Tester.TestChannelCallable());
    }

    @Test
    public void testRoleCheckBypassAllowedResult() throws Exception {
        final VirtualChannel channel = j.createOnlineSlave().getChannel();
        assertNotNull(channel);
        RequiredRoleCheck.SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.add(Tester.NonRoleCheckingCallable.class.getName());
        try {
            IllegalStateException ex = assertThrows(IllegalStateException.class, () -> channel.call(new Tester.TestChannelCallable()));
            assertThat(ex.getMessage(), containsString("A Callable not performing a role check successfully executed"));
        } finally {
            RequiredRoleCheck.SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.remove(Tester.NonRoleCheckingCallable.class.getName());
        }
    }

    @Test
    public void testFileWrapperExecutionDependingOnBlockList() throws Exception {
        final VirtualChannel channel = j.createOnlineSlave().getChannel();
        assertNotNull(channel);
        channel.call(new Tester.TestChannelCallable());
        ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.remove("hudson.FilePath$FileCallableWrapper");
        try {
            IllegalStateException ex = assertThrows(IllegalStateException.class, () -> channel.call(new Tester.TestChannelCallable()));
            assertThat(ex.getMessage(), containsString("A FileCallable successfully executed, indicating that file access is not fully blocked"));
        } finally {
            ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add("hudson.FilePath$FileCallableWrapper");
        }
    }

    @Test
    public void testGenericBlockedAndAllowedCallables() throws Exception {
        final VirtualChannel channel = j.createOnlineSlave().getChannel();
        ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.remove(Tester.BlockedByDefaultNoOpAgentToControllerCallable.class.getName());
        try {
            assertNotNull(channel);
            IllegalStateException ex = assertThrows(IllegalStateException.class, () -> channel.call(new Tester.TestChannelCallable()));
            assertThat(ex.getMessage(), containsString("BlockedByDefaultNoOpAgentToControllerCallable successfully executed, indicating that the block list is ineffective or customized"));
        } finally {
            ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add(Tester.BlockedByDefaultNoOpAgentToControllerCallable.class.getName());
        }

        ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add(Tester.AllowedByDefaultNoOpAgentToControllerCallable.class.getName());
        try {
            assertNotNull(channel);
            IllegalStateException ex = assertThrows(IllegalStateException.class, () -> channel.call(new Tester.TestChannelCallable()));
            assertThat(ex.getMessage(), containsString("Exception thrown for AllowedByDefaultNoOpAgentToControllerCallable"));
        } finally {
            ConfigurableCallableBlocker.SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.remove(Tester.AllowedByDefaultNoOpAgentToControllerCallable.class.getName());
        }

        // We cannot really test the case of an old channel pre-dating the ConfigurableCallableBlocker, since that only happens when this plugin is dynamically loaded
    }
}
