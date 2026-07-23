/*
 * Copyright (c) [2016] [ <ether.camp> ]
 * This file is part of the ethereumJ library.
 *
 * The ethereumJ library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ethereumJ library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the ethereumJ library. If not, see <http://www.gnu.org/licenses/>.
 */

package org.tron.common.crypto.jce;

import android.os.Build;


import org.tron.common.utils.LogUtils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;

public final class ECKeyFactory {

    //    public static final String ALGORITHM = "EC";
    public static final String ALGORITHM = "ECDSA";

    private static final String algorithmAssertionMsg =
            "Assumed the JRE supports EC key factories";

    private ECKeyFactory() {
    }

    public static KeyFactory getInstance() {
        return Holder.INSTANCE;
    }


    public static KeyFactory getInstance(final Provider provider) {
        KeyFactory keyFactory;
        try {
            //adapte  Android P and later，otherwise throws NoSuchAlgorithmException
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                keyFactory = KeyFactory.getInstance(ALGORITHM);
            } else {
                keyFactory = KeyFactory.getInstance(ALGORITHM, provider);
            }
            return keyFactory;
        } catch (NoSuchAlgorithmException ex) {
            try {
                //adapte HUAWEI Brand phone exception
                keyFactory = KeyFactory.getInstance(ALGORITHM, provider);
                return keyFactory;
            } catch (NoSuchAlgorithmException e) {
                LogUtils.e(e);
                // The inner failure e is the real root cause of the HUAWEI fallback
                // failing; keep it as the cause and only suppress the outer ex so
                // neither reason is lost when diagnosing the fallback path.
                AssertionError error = new AssertionError(algorithmAssertionMsg, e);
                error.addSuppressed(ex);
                throw error;
            }
        }
    }

    private static class Holder {
        private static final KeyFactory INSTANCE;

        static {
            try {
                INSTANCE = KeyFactory.getInstance(ALGORITHM);
            } catch (NoSuchAlgorithmException ex) {
                throw new AssertionError(algorithmAssertionMsg, ex);
            }
        }
    }
}
