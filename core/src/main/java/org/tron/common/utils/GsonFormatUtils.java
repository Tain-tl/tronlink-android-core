package org.tron.common.utils;


import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.ToNumberPolicy;
import com.google.gson.TypeAdapter;
import com.google.gson.internal.LinkedTreeMap;
import com.google.gson.reflect.TypeToken;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;


public class GsonFormatUtils {
    private static Gson gson = null;

    static {
        if (gson == null) {
            gson = new GsonBuilder()
                    .setObjectToNumberStrategy(ToNumberPolicy.LAZILY_PARSED_NUMBER)
                    .setNumberToNumberStrategy(ToNumberPolicy.LAZILY_PARSED_NUMBER)
                    .create();
        }
    }

    private GsonFormatUtils() {
    }


    /**
     * convert  Object to json string
     *
     * @param object
     * @return
     */
    public static String toGsonString(Object object) {
        String gsonString = null;
        if (gson != null) {
            gsonString = gson.toJson(object);
        }
        return gsonString;
    }


    /**
     * convert GsonString to generic bean
     *
     * @param gsonString
     * @param cls
     * @return
     */
    public static <T> T gsonToBean(String gsonString, Class<T> cls) {
        T t = null;
        if (gson != null) {
            t = gson.fromJson(gsonString, cls);
        }
        return t;
    }


    /**
     * convert to List
     *
     * @param gsonString
     * @param cls
     * @return
     */
    public static <T> List<T> gsonToList(String gsonString, Class<T> cls) {
        List<T> list = null;
        if (gson != null) {
            list = gson.fromJson(gsonString, new TypeToken<List<T>>() {
            }.getType());
        }
        return list;
    }

    public static <T> List<T> gsonToListFixDouble(String gsonString, Class<T> cls) {
        List<T> list = null;
        try{
            Gson gson = new GsonBuilder()
                    .registerTypeAdapter(new TypeToken<List<Object>>() {
                    }.getType(), new GsonFormatUtils.DoubleTypeAdapter())
                    .create();
            list = gson.fromJson(gsonString, new TypeToken<List<Object>>() {
            }.getType());
        }catch (Exception e){
            LogUtils.e(e);
        }
        return list;
    }


    public static class DoubleTypeAdapter extends TypeAdapter<Object> {
        private final TypeAdapter<Object> delegate = new Gson().getAdapter(Object.class);

        @Override
        public void write(JsonWriter out, Object value) throws IOException {
            delegate.write(out, value);
        }


        public Object read(JsonReader in) throws IOException {
            JsonToken token = in.peek();
            switch (token) {
                case BEGIN_ARRAY:
                    List<Object> list = new ArrayList<Object>();
                    in.beginArray();
                    while (in.hasNext()) {
                        list.add(read(in));
                    }
                    in.endArray();

                    return list;

                case BEGIN_OBJECT:
                    Map<String, Object> map = new LinkedTreeMap<String, Object>();
                    in.beginObject();
                    while (in.hasNext()) {
                        map.put(in.nextName(), read(in));
                    }
                    in.endObject();
                    return map;

                case STRING:
                    return in.nextString();

                case NUMBER:
                    String n = in.nextString();
                    if (n.indexOf('.') != -1) {
                        return Double.parseDouble(n);
                    }
                    return new BigDecimal(n).toPlainString();

                case BOOLEAN:
                    return in.nextBoolean();

                case NULL:

                    in.nextNull();
                    return null;

                default:
                    throw new IllegalStateException();
            }
        }

    }
}
