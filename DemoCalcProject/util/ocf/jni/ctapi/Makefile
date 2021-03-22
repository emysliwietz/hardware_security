#
# Makefile for ctapi-jni project
#
# You need to define JAVA_HOME before calling make, e.g.
#
# JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 make
#
# Enable debuggin with -DDEBUG
#

VERS    = 1.3.0

# all:    libctapi-jni-i386.so libctapi-jni-amd64.so
all:    libctapi-jni-amd64.so

clean:
	-rm -f *.o
	-rm -f *.so
	-rm -f *~

ctapi-jni.h:                  ../../src/de/cardcontact/ctapi/CTAPI.java
	javah -classpath ../../bin -o ctapi-jni.h de.cardcontact.ctapi.CTAPI

libctapi-jni-amd64.so:        ctapi-jni.cpp ctapi-jni.h
	g++ -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux ctapi-jni.cpp -o libctapi-jni-amd64.so -shared -ldl -fPIC -m64

libctapi-jni-i386.so:         ctapi-jni.cpp ctapi-jni.h
	g++ -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux ctapi-jni.cpp -o libctapi-jni-i386.so -shared -ldl -m32
