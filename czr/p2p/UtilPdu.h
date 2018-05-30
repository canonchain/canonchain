#pragma once

#ifndef UTILPDU_H_
#define UTILPDU_H_

#include "ostype.h"
#include <set>
#include <map>
#include <list>
#include <string>

// exception code
#define ERROR_CODE_PARSE_FAILED 		1
#define ERROR_CODE_WRONG_SERVICE_ID		2
#define ERROR_CODE_WRONG_COMMAND_ID		3
#define ERROR_CODE_ALLOC_FAILED			4
//预期的pdu
class CPduException {
public:
	CPduException(uint32_t service_id, uint32_t command_id, uint32_t error_code, const char* error_msg)
	{
		m_service_id = service_id;//服务ID
		m_command_id = command_id;//命令字
		m_error_code = error_code;
		m_error_msg = error_msg;
	}

	CPduException(uint32_t error_code, const char* error_msg)
	{
		m_service_id = 0;
		m_command_id = 0;
		m_error_code = error_code;
		m_error_msg = error_msg;
	}

	virtual ~CPduException() {}

	uint32_t GetServiceId() { return m_service_id; }
	uint32_t GetCommandId() { return m_command_id; }
	uint32_t GetErrorCode() { return m_error_code; }
	char* GetErrorMsg() { return (char*)m_error_msg.c_str(); }
private:
	uint32_t	m_service_id;
	uint32_t	m_command_id;
	uint32_t	m_error_code;
	std::string		m_error_msg;
};
//简单buffer类型
class CSimpleBuffer
{
public:
	CSimpleBuffer();
	~CSimpleBuffer();
	uchar_t*  GetBuffer() { return m_buffer; }
	uint32_t GetAllocSize() { return m_alloc_size; }
	uint32_t GetWriteOffset() { return m_write_offset; }
	void IncWriteOffset(uint32_t len) { m_write_offset += len; }//增加写偏移

	void Extend(uint32_t len);
	uint32_t Write(void* buf, uint32_t len);
	uint32_t Read(void* buf, uint32_t len);
private:
	uchar_t*	m_buffer;
	uint32_t	m_alloc_size;
	uint32_t	m_write_offset;
};
//简单字节流
class CByteStream
{
public:
	CByteStream(uchar_t* buf, uint32_t len);
	CByteStream(CSimpleBuffer* pSimpBuf, uint32_t pos);
	~CByteStream() {}

	unsigned char* GetBuf() { return m_pSimpBuf ? m_pSimpBuf->GetBuffer() : m_pBuf; }
	uint32_t GetPos() { return m_pos; }
	uint32_t GetLen() { return m_len; }
	void Skip(uint32_t len)
	{
		m_pos += len;
		if (m_pos > m_len)
		{
			throw CPduException(ERROR_CODE_PARSE_FAILED, "parase packet failed!");
		}
	}
	//读有符号16位
	static int16_t ReadInt16(uchar_t* buf);
	//读无符号16位
	static uint16_t ReadUint16(uchar_t* buf);
	//读有符号32位
	static int32_t ReadInt32(uchar_t* buf);
	//读无符号32位
	static uint32_t ReadUint32(uchar_t* buf);
	//写有符号16位
	static void WriteInt16(uchar_t* buf, int16_t data);
	//写无符号16位
	static void WriteUint16(uchar_t* buf, uint16_t data);
	//写有符号32位
	static void WriteInt32(uchar_t* buf, int32_t data);
	//写无符号32位
	static void WriteUint32(uchar_t* buf, uint32_t data);

	void operator << (int8_t data);
	void operator << (uint8_t data);
	void operator << (int16_t data);
	void operator << (uint16_t data);
	void operator << (int32_t data);
	void operator << (uint32_t data);

	void operator >> (int8_t& data);
	void operator >> (uint8_t& data);
	void operator >> (int16_t& data);
	void operator >> (uint16_t& data);
	void operator >> (int32_t& data);
	void operator >> (uint32_t& data);
	//写字符串
	void WriteString(const char* str);
	//写带有长度的字符串
	void WriteString(const char* str, uint32_t len);
	//读字符串
	char* ReadString(uint32_t& len);
	//写数据,长度为len的data数据
	void WriteData(uchar_t* data, uint32_t len);
	//读数据，存到m_pBuf中
	uchar_t* ReadData(uint32_t& len);
private:
	void _WriteByte(void* buf, uint32_t len);
	void _ReadByte(void* buf, uint32_t len);
private:
	CSimpleBuffer*	m_pSimpBuf;
	uchar_t*		m_pBuf;
	uint32_t		m_len;
	uint32_t		m_pos;
};

#endif /* UTILPDU_H_ */
