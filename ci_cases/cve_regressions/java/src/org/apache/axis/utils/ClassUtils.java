package org.apache.axis.utils;

public class ClassUtils
{
    public static Class forName(String className)
        throws ClassNotFoundException
    {
        return Class.forName(className);
    }
}
