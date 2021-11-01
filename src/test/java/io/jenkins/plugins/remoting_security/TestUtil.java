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

import org.junit.function.ThrowingRunnable;

import java.io.IOException;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class TestUtil {

    public static SecurityException assertThrowsIOExceptionCausedBySecurityException(ThrowingRunnable runnable) {
        return assertThrowsIOExceptionCausedBy(SecurityException.class, runnable);
    }

    public static <X extends Throwable> X assertThrowsIOExceptionCausedBy(Class<X> causeClass, ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (IOException ex) {
            final Throwable cause = ex.getCause();
            assertTrue("IOException with message: '" + ex.getMessage() + "' wasn't caused by " + causeClass + ": " + (cause == null ? "(null)" : (cause.getClass().getName() + ": " + cause.getMessage())),
                    cause != null && causeClass.isAssignableFrom(cause.getClass()));
            return causeClass.cast(cause);
        } catch (Throwable t) {
            fail("Threw other Throwable: " + t.getClass() + " with message " + t.getMessage());
        }
        fail("Expected exception but passed");
        return null;
    }
}
