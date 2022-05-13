#源文件通配符
SOURCE	:=	$(wildcard *.c) $(wildcar *.cpp)
OBJS	:=	$(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(SOURCE)))

#生成执行文件名
TARGET	:=	tcp_chat_service

#指令和参数，库名
CC	:=	gcc
LIB	:=	-lpcap
LDFLAGS	:=
DEFINES	:=
INCLUDE	:=	-I.
CFLAGS	:=	-g	-Wall	-o3	$(DEFINES)	$(INCLUDE)
CXXFLAGS:=	$(CFLAGS)	-DHAVE_CONFIG_H
.PHONY	:=	everything	objs	clean	allclean	rebuild
everything	:$(TARGET)
all	:$(TARGET)
objs	:$(OBJS)
rebuild	:	allclean	everything

#删除输出文件(.o .so)
clean:
	rm	-fr	*.so
	rm	-fr	*.o

#删除所有输出文件
allclean	:clean
	rm -fr $(TARGET)

$(TARGET)	:	$(OBJS)
	$(CC)	$(CXXFLAGS)	$(OBJS)	-o	$(TARGET)	$(LIBS)
