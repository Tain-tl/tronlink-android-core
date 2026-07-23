package org.tron.config;

public interface Parameter {

    interface CommonConstant {
        byte ADD_PRE_FIX_BYTE = (byte) 0x41;   //a0 + address  ,a0 is version
        String ADD_PRE_FIX_STRING = "41";
        int ADDRESS_SIZE = 21;
        int BASE58CHECK_ADDRESS_SIZE = 35;
    }

    interface ResConstant {
        int BANDWIDTH_COST = 70;
        int SIGNATURE_COST = 65;

        // NOTE: legacy factor, do NOT use for exact fee math (binary floating point).
        // Kept as-is (unused in core); if fee arithmetic is ever added, use long SUN
        // or BigDecimal instead. Scan 2026-07-21 Q-14, accepted.
        double feeBandWidth = 0.001;//1 bandwidth = 0.00014TRX  // shasta dappchain

        long feeLimit = 225000000;

    }

    interface ShieldConstant {

        byte[] ZTRON_EXPANDSEED_PERSONALIZATION = {'Z', 't', 'r', 'o', 'n', '_', 'E', 'x',
                'p', 'a', 'n', 'd', 'S', 'e', 'e', 'd'};
        int ZC_DIVERSIFIER_SIZE = 11;
        public static final int ZC_OUTPUT_DESC_MAX_SIZE = 10;
        String PAYMENT_ADDRESS_FORMAT_WRONG = "paymentAddress format is wrong";
    }

    class NetConstant {
        public static int triggerType = 1; // 1 means trigger, 2 represent  triggerConstant
    }

    interface CreateWalletType {
        int TYPE_CREATE_WALLET = 0;
        int TYPE_IMPORT_MNEMONIC = 1;
        int TYPE_IMPORT_PRIKEY = 2;
        int TYPE_IMPORT_KEYSTORE = 3;
        int TYPE_IMPORT_OBSERVED = 4;
        int TYPE_IMPORT_MNEMONIC_HD = 5;  // only net use
        int TYPE_IMPORT_MNEMONIC_NO_HD = 6;
        int TYPE_IMPORT_SAMSUNG_HD = 7;
        int TYPE_IMPORT_LEDGER = 8;
        int TYPE_IMPORT_COLD = 9;
    }


}
