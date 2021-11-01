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

import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.remoting.Callable;
import hudson.remoting.ChannelBuilder;
import jenkins.security.ChannelConfigurator;
import org.jenkinsci.remoting.CallableDecorator;
import org.jenkinsci.remoting.Role;
import org.jenkinsci.remoting.RoleChecker;
import org.jenkinsci.remoting.RoleSensitive;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Ensures that {@link Callable}s perform a role check in their
 * {@code RoleSensitive#checkRoles} implementation and rejects them otherwise.
 */
@Restricted(NoExternalUse.class)
public class RequiredRoleCheck extends CallableDecorator {
    private static /* non-final for Groovy */ boolean CALLABLES_CAN_IGNORE_ROLECHECKER = Boolean.getBoolean(RequiredRoleCheck.class.getName() + ".allCallablesCanIgnoreRoleChecker");

    /* package */ static final Set<String> SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER = new HashSet<>();

    private static final Logger LOGGER = Logger.getLogger(RequiredRoleCheck.class.getName());

    static {
        final String propertyName = RequiredRoleCheck.class.getName() + ".specificCallablesCanIgnoreRoleChecker";
        final String property = System.getProperty(propertyName); // Compatibility with low core dependency
        if (property != null) {
            LOGGER.log(Level.INFO, () -> "Allowing the following callables to bypass role checker requirement: " + property);
            SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.addAll(Arrays.stream(property.split(",")).map(String::trim).collect(Collectors.toSet()));
        }

        // These callables are patched upstream, but may not be on instances with this plugin:
        SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.add("hudson.remoting.Channel$IOSyncer");
        SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.add("hudson.remoting.Channel$SetMaximumBytecodeLevel");
        SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.add("hudson.remoting.PingThread$Ping");
    }

    private static boolean isCallableProhibitedByRequiredRoleCheck(Callable<?, ?> callable) {
        if (CALLABLES_CAN_IGNORE_ROLECHECKER) {
            LOGGER.log(Level.FINE, () -> "Allowing all callables to ignore RoleChecker");
            return false;
        }

        if (callable.getClass().getName().startsWith("hudson.remoting.RemoteInvocationHandler")) {
            LOGGER.log(Level.FINEST, () -> "Callable " + callable.getClass().getName() + " is an RPCRequest");
            return false;
        }

        if (SPECIFIC_CALLABLES_CAN_IGNORE_ROLECHECKER.contains(callable.getClass().getName())) {
            LOGGER.log(Level.FINER, () -> "Callable " + callable.getClass().getName() + " is allowed through override");
            return false;
        }

        return true;
    }

    @Override
    public <V, T extends Throwable> Callable<V, T> userRequest(Callable<V, T> op, Callable<V, T> stem) {
        try {
            RequiredRoleCheckerWrapper wrapped = new RequiredRoleCheckerWrapper();
            stem.checkRoles(wrapped);
            if (wrapped.isChecked()) {
                LOGGER.log(Level.FINEST, () -> "Callable " + stem.getClass().getName() + " checked roles");
            } else if (isCallableProhibitedByRequiredRoleCheck(stem)) {
                LOGGER.log(Level.INFO, () -> "Rejecting callable " + stem.getClass().getName() + " for ignoring RoleChecker in #checkRoles, see https://www.jenkins.io/redirect/remoting-security-workaround/");
                throw new SecurityException("Security hardening prohibits the Callable implementation " + stem.getClass().getName() + " from ignoring RoleChecker, see https://www.jenkins.io/redirect/remoting-security-workaround/");
            }
        } catch (AbstractMethodError e) {
            // Ignore, will be caught by core default behavior
        }
        return stem;
    }

    /**
     * Dummy role checker that just records whether the {@link RoleSensitive} calls
     * {@code #check}.
     */
    private static class RequiredRoleCheckerWrapper extends RoleChecker {
        private boolean checked;

        @Override
        public void check(RoleSensitive subject, Role... expected) throws SecurityException {
            checked = true;
        }

        @Override
        public void check(RoleSensitive subject, Role expected) throws SecurityException {
            checked = true;
        }

        @Override
        public void check(RoleSensitive subject, Collection<Role> expected) throws SecurityException {
            checked = true;
        }

        public boolean isChecked() {
            return checked;
        }
    }

    @Extension
    public static class ChannelConfiguratorImpl extends ChannelConfigurator {
        @Override
        public void onChannelBuilding(ChannelBuilder builder, @Nullable Object context) {
            LOGGER.log(Level.FINE, () -> "Registering " + this + " on: " + builder + " for context: " + context);
            builder.with(new RequiredRoleCheck());
        }
    }
}
