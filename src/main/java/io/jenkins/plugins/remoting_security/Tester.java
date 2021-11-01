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

import hudson.FilePath;
import hudson.model.Node;
import hudson.model.Slave;
import hudson.remoting.Callable;
import hudson.remoting.Channel;
import hudson.remoting.VirtualChannel;
import hudson.slaves.SlaveComputer;
import jenkins.SlaveToMasterFileCallable;
import jenkins.model.Jenkins;
import jenkins.security.MasterToSlaveCallable;
import jenkins.security.SlaveToMasterCallable;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

@Restricted(NoExternalUse.class)
public class Tester {
    private static final Logger LOGGER = Logger.getLogger(Tester.class.getName());

    public static void testChannelToAgent(String agentName) throws Exception {
        if (agentName == null) {
            throw new IllegalStateException("No name was provided.");
        }
        final Node agent = Jenkins.get().getNode(agentName);
        if (agent == null) {
            throw new IllegalStateException("No agent '" + agentName + "' was found. Wrong name?");
        }
        final VirtualChannel channel = agent.getChannel();
        if (channel == null) {
            throw new IllegalStateException("Can only check online agent, but channel was null");
        }
        channel.call(new TestChannelCallable());
    }

    public static void testChannelToAgent(Slave agent) throws Exception {
        if (agent == null) {
            throw new IllegalStateException("No agent was provided. Wrong name?");
        }
        final VirtualChannel channel = agent.getChannel();
        if (channel == null) {
            throw new IllegalStateException("Can only check online agent, but channel was null");
        }
        channel.call(new TestChannelCallable());
    }

    public static void testChannelToAgent(SlaveComputer agent) throws Exception {
        if (agent == null) {
            throw new IllegalStateException("No agent was provided. Wrong name?");
        }
        final Channel channel = agent.getChannel();
        if (channel == null) {
            throw new IllegalStateException("Can only check online agent, but channel was null");
        }
        channel.call(new TestChannelCallable());
    }

    public static void testCurrentChannel() throws Exception {
        final VirtualChannel channelToController = getChannelToController();
        if (channelToController == null) {
            throw new IllegalStateException("This method can only be invoked from the agent side of an agent/controller channel");
        }

        try {
            channelToController.call(new NonRoleCheckingCallable());
            throw new IllegalStateException("No exception thrown for NonRoleCheckingCallable");
        } catch (IOException ex) {
            if (ex.getCause() instanceof SecurityException) {
                LOGGER.log(Level.FINE, "Got an expected exception for NonRoleCheckingCallable", ex);
            } else {
                throw new IllegalStateException("Unexpected exception for NonRoleCheckingCallable", ex);
            }
        }

        try {
            new FilePath(channelToController, "test").act(new NoOpFileCallable());
            throw new IllegalStateException("No exception thrown for NoOpFileCallable");
        } catch (IOException ex) {
            if (ex.getCause() instanceof SecurityException) {
                LOGGER.log(Level.FINE, "Got an expected exception for NoOpFileCallable", ex);
            } else {
                throw new IllegalStateException("Unexpected exception for NoOpFileCallable", ex);
            }
        }

        try {
            channelToController.call(new BlockedByDefaultNoOpAgentToControllerCallable());
            throw new IllegalStateException("No exception thrown for BlockedByDefaultNoOpAgentToControllerCallable");
        } catch (IOException ex) {
            // Caught when execution is rejected
            if (ex.getCause() instanceof SecurityException) {
                LOGGER.log(Level.FINE, "Got an expected exception for BlockedByDefaultNoOpAgentToControllerCallable", ex);
            } else {
                throw new IllegalStateException("Unexpected exception for BlockedByDefaultNoOpAgentToControllerCallable", ex);
            }
        }

        try {
            channelToController.call(new AllowedByDefaultNoOpAgentToControllerCallable());
        } catch (IOException ex) {
            // Caught when execution is rejected
            if (ex.getCause() instanceof SecurityException) {
                throw new IllegalStateException("Exception thrown for AllowedByDefaultNoOpAgentToControllerCallable");
            } else {
                throw new IllegalStateException("Unexpected exception for AllowedByDefaultNoOpAgentToControllerCallable", ex);
            }
        }
    }

    public static class TestChannelCallable extends MasterToSlaveCallable<Object, Exception> {
        @Override
        public Object call() throws Exception {
            testCurrentChannel();
            return null;
        }
    }

    private static VirtualChannel getChannelToController() {
        if (Jenkins.getInstanceOrNull() != null) {
            return null; // on controller, do not bother
        }
        // Basically copied from AgentComputerUtil to work on <2.235
        final Channel channel = Channel.current();
        if (channel == null) {
            return null;
        }
        // Handle both 2.306 and earlier ("slave") and 2.307 and newer ("agent")
        if (Boolean.TRUE.equals(channel.getProperty("slave")) || Boolean.TRUE.equals(channel.getProperty("agent"))) {
            return channel;
        }
        return null;
    }

    public static class NonRoleCheckingCallable implements Callable<Object, Exception> {
        @Override
        public Object call() throws Exception {
            throw new IllegalStateException("A Callable not performing a role check successfully executed");
        }

        @Override
        public void checkRoles(RoleChecker roleChecker) throws SecurityException {
            // Deliberately left empty
        }
    }

    public static class NoOpFileCallable extends SlaveToMasterFileCallable<Object> {
        @Override
        public Object invoke(File f, VirtualChannel channel) throws IOException, InterruptedException {
            throw new IllegalStateException("A FileCallable successfully executed, indicating that file access is not fully blocked");
        }
    }

    public static class BlockedByDefaultNoOpAgentToControllerCallable extends SlaveToMasterCallable<Object, Exception> {
        @Override
        public Object call() throws Exception {
            throw new IllegalStateException("BlockedByDefaultNoOpAgentToControllerCallable successfully executed, indicating that the block list is ineffective or customized");
        }
    }

    public static class AllowedByDefaultNoOpAgentToControllerCallable extends SlaveToMasterCallable<Object, Exception> {
        @Override
        public Object call() throws Exception {
            return null;
        }
    }
}
