package org.tron.metrics.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;

import java.util.Map;


public class GsonUtils {
    private static final Gson gson;

    static {
        gson = new GsonBuilder()
                .setObjectToNumberStrategy(ToNumberPolicy.LAZILY_PARSED_NUMBER)
                .create();
    }

    private GsonUtils() {
    }

    public static String toGsonString(Object object) {
        String gsonString = null;
        if (gson != null) {
            gsonString = gson.toJson(object);
        }
        return gsonString;
    }

    public static <T> T gsonToBean(String gsonString, Class<T> cls) {
        T t = null;
        if (gson != null) {
            t = gson.fromJson(gsonString, cls);
        }
        return t;
    }

    public static Map<String, Integer> gsonToMap(String gsonString) {
        return new Gson().fromJson(gsonString, new TypeToken<Map<String, Integer>>() {
        }.getType());
    }

}
