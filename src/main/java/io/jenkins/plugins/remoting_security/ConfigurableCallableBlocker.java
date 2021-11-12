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
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * Allows blocking any callable regardless of the result of its role check.
 * The list of callables is customizable to allow blocked-by-default callables
 * (through Groovy script), or block additional callables (through system property
 * or Groovy script).
 */
@Restricted(NoExternalUse.class)
public class ConfigurableCallableBlocker extends CallableDecorator {
    /* package */ static final Set<String> SPECIFIC_CALLABLES_TO_ALWAYS_REJECT = new HashSet<>();

    private static final Logger LOGGER = Logger.getLogger(ConfigurableCallableBlocker.class.getName());

    static {
        final String propertyName = ConfigurableCallableBlocker.class.getName() + ".additionalCallablesToAlwaysReject";
        final String property = System.getProperty(propertyName); // Compatibility with low core dependency
        if (property != null) {
            LOGGER.log(Level.INFO, () -> "Rejecting the following callables regardless of role checker result: " + property);
            SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.addAll(Arrays.stream(property.split(",")).map(String::trim).collect(Collectors.toSet()));
        }
        SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add("hudson.scm.SubversionSCM$DescriptorImpl$SshPublicKeyCredential$1"); // SECURITY-2506
        SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add("hudson.FilePath$FileCallableWrapper"); // SECURITY-2455
        SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add("org.jenkinsci.squashtm.tawrapper.TestListSaver$TestListCallable"); // SECURITY-2525
        SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.add(Tester.BlockedByDefaultNoOpAgentToControllerCallable.class.getName()); // Test utility in this plugin
    }

    @Override
    public <V, T extends Throwable> Callable<V, T> userRequest(Callable<V, T> op, Callable<V, T> stem) {
        if (SPECIFIC_CALLABLES_TO_ALWAYS_REJECT.contains(op.getClass().getName())) {
            LOGGER.log(Level.INFO, () -> "Rejecting callable " + op + " of type " + op.getClass() + " regardless of role checker, see https://www.jenkins.io/redirect/remoting-security-workaround/");
            throw new SecurityException("Custom security configuration prohibits execution of " + op + " of type " + op.getClass() + ", see https://www.jenkins.io/redirect/remoting-security-workaround/");
        } else {
            LOGGER.log(Level.FINEST, () -> "Not rejecting execution of " + op + " of type " + op.getClass());
        }
        return stem;
    }

    @Extension
    public static class ChannelConfiguratorImpl extends ChannelConfigurator {
        @Override
        public void onChannelBuilding(ChannelBuilder builder, @Nullable Object context) {
            LOGGER.log(Level.FINE, () -> "Registering " + this + " on: " + builder + " for context: " + context);
            builder.with(new ConfigurableCallableBlocker());
        }
    }
}
