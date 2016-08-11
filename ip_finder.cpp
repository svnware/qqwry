#include "ip_finder.hpp"

#include <fcntl.h>  
#include <sys/types.h>  
#include <math.h>  
#include <stdio.h>  
#include <string.h>  
#include <sys/stat.h>  
#include <errno.h>   
#include <locale>
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)

#else
#include <unistd.h>  
#include <sys/mman.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iconv.h>
#endif

#define OUTLEN 255
#define SHARE_MEMORY_FILE "/tmp/qqwry.dat"
#define UNKNOWN "Unknown"
#define SHARE_MEMORY_SIZE 10485760 // 10M > qqwry.dat
#define RECORD_LEN 7

namespace is{
namespace common{
namespace location{
ip_finder::ip_finder()
  : pshare_(NULL)
  , pbegin_(NULL)
  , pend_(NULL)
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)
  , hFileMap_(NULL)
#endif
  , total_record_(0)
{

}

ip_finder::~ip_finder()
{
  destroy();
}

int ip_finder::initialize(const std::string& file)
{
  if (file.empty()) return -1;
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)
	HANDLE hFile = CreateFile(file.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}

	hFileMap_ = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hFileMap_ == NULL) {
		return GetLastError();
	}

	DWORD dwFileSizeHigh;
	__int64 qwFileSize = GetFileSize(hFile, &dwFileSizeHigh);

	CloseHandle(hFile);

	pshare_ = (PBYTE)MapViewOfFile(hFileMap_, FILE_MAP_READ, 0, 0, 0);
	if (pshare_ == NULL) {
		return GetLastError();
	}
#else
	if (pshare_ == NULL) {
		int fd = open(file.c_str(), O_RDONLY); 
		if (-1 == fd) {
			return errno;
		}

		struct stat sb;
		if (-1 == fstat(fd, &sb)) {
			return errno;
		}

		void* pmmap = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
		if (MAP_FAILED == pmmap) {
			return errno;
		}

		pshare_ = (unsigned char*)pmmap;
 
		close(fd);   
	}
#endif

	pbegin_ = pshare_ + get_long4(pshare_);
	pend_ = pshare_ + get_long4(pshare_ + 4);
	total_record_ = (get_long4(pshare_ + 4) - get_long4(pshare_)) / RECORD_LEN + 1;  

	return 0;
}

void ip_finder::destroy()
{ 
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)
	if (pshare_ != NULL) {
		UnmapViewOfFile(pshare_);
		pshare_ = NULL;
	}

	if (hFileMap_ != INVALID_HANDLE_VALUE) {
		CloseHandle(hFileMap_);
		hFileMap_ = INVALID_HANDLE_VALUE;
	}
#else
	if (pshare_ != NULL) {
    munmap(pshare_, SHARE_MEMORY_SIZE);
	  pshare_ = NULL;
  }
#endif
}

bool ip_finder::get_ip_original_info(const std::string& ipstr, std::string& country, std::string& area)
{  
  if (ipstr.empty() || pshare_ == NULL || pbegin_ == NULL || pend_ == NULL || total_record_ == 0)
    return false;

  location_t loc;
  memset(&loc, 0x0, sizeof(location_t)); 

  unsigned char* search = pshare_;
  unsigned char* pos = pshare_;  
  unsigned char* firstip = 0;
 
  boost::uint32_t ip = ntohl(inet_addr(ipstr.c_str()));  
  firstip = pbegin_;  

  long l = 0;  
  long u = total_record_;  
  long i = 0;  
  unsigned char* findip = firstip;  
  boost::uint32_t beginip = 0;  
  boost::uint32_t endip = 0; 

  //二分法查找  
  while (l <= u)  
  {  
    i = (l + u) / 2;  
    pos = firstip + i * RECORD_LEN;  
    beginip = get_long4(pos);  
    pos += 4;  
    if (ip < beginip) {  
      u = i - 1;      
    } else {  
      endip = get_long4(search + get_long3(pos));  
      if (ip > endip) {  
        l = i + 1;          
      } else {  
        findip = firstip + i * RECORD_LEN;  
        break;      
      }  
    }  
  }

  long offset = get_long3(findip + 4);  
  pos = search + offset;  
  endip = get_long4(pos);
  pos += 4;  

  //boost::uint32_t j = htonl(beginip);  
  //inet_ntop(AF_INET, &j, loc.beginip, INET6_ADDRSTRLEN);
  //j = htonl(endip);  
  //inet_ntop(AF_INET, &j, loc.endip, INET6_ADDRSTRLEN);

  unsigned char* byte = pos; // 标志字节
  pos++;  

  switch (*byte) 
  {  
  case REDIRECT_MODE_1:
    {   
      long countryOffset = get_long3(pos); // 重定向地址  
      pos += 3;  
      pos = search + countryOffset;  
      byte = pos; // 标志字节
      pos++;

      switch (*byte) 
      {  
      case REDIRECT_MODE_2:
        {  
			loc.pcountry_ = search + get_long3(pos);  
			pos = search + countryOffset + 4;  
			loc.parea_ = get_area(search, pos);  
        }  
        break;  
      default: 
        {
			loc.pcountry_ = byte; 
			if (loc.pcountry_ && loc.pcountry_[0])
				loc.parea_ = get_area(search, loc.pcountry_ + strlen((const char*)loc.pcountry_) + 1);  
			else
				return false;
        }  
        break;  
      }  
    }  
    break;  
  case REDIRECT_MODE_2:
    {  
		loc.pcountry_ = search + get_long3(pos);  
		loc.parea_ = get_area(search, search + offset + 8); // search + offset + 8;
    }  
    break;  
  default:
    { 
		loc.pcountry_ = byte; 
		if (loc.pcountry_ && loc.pcountry_[0])
			loc.parea_ = get_area(search, loc.pcountry_ + strlen((const char*)loc.pcountry_) + 1); 
		else
			return false;
    }  
    break;  
  }  

	if (loc.pcountry_ && loc.pcountry_[0])
		country.assign((const char*)loc.pcountry_, strlen((const char*)loc.pcountry_));
	if (loc.parea_ && loc.parea_[0])
		area.assign((const char*)loc.parea_, strlen((const char*)loc.parea_));

  return true;
}  

unsigned char* ip_finder::get_area(unsigned char* pserach, unsigned char* pos) 
{  
  unsigned char* byte = pos; // 标志字节
  pos++; 

  switch (*byte) {
  //case REDIRECT_MODE_0:
  //  break;  
  case REDIRECT_MODE_1:  
  case REDIRECT_MODE_2: // 标志字节为1或2，表示区域信息被重定向  
    return pserach + get_long3(pos);  
    break;  
  default: // 否则，表示区域信息没有被重定向
    return byte;  
    break;  
  }  

  return NULL;
}  

boost::uint32_t ip_finder::get_long4(const unsigned char* pos) 
{  
  boost::uint32_t result = pos[0];
	for (boost::uint32_t i = 0; i < 4; i++)
		result |= ((boost::uint32_t)pos[i])<<(8*i);

  return result; 
}  

boost::uint32_t ip_finder::get_long3(const unsigned char* pos) 
{  
  boost::uint32_t result = pos[0];
	for (boost::uint32_t i = 0; i < 3; i++)
		result |= ((boost::uint32_t)pos[i])<<(8*i);

  return result;
}  

int ip_finder::utf8togb2312(const std::string& instr, std::string& outstr) 
{ 
  char outbuf[OUTLEN] = {0};
  int ret = code_convert("utf-8", "gb2312", instr.c_str(), instr.length(), outbuf, OUTLEN);
  if (ret == 0) {
	  outstr = outbuf;
  }
  return ret;
} 

int ip_finder::gb2312toutf8(const std::string& instr, std::string& outstr) 
{ 
  char outbuf[OUTLEN] = {0};
  int ret = code_convert("gb2312", "utf-8", instr.c_str(), instr.length(), outbuf, OUTLEN);
  if (ret == 0) {
	outstr = outbuf;
  }

  return ret;
} 

int ip_finder::code_convert(const std::string& from_charset, const std::string& to_charset, const char* inbuf, size_t inlen, char* outbuf, size_t outlen) 
{ 
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)

#else
  char** pin = const_cast<char**>(&inbuf); 
  char** pout = &outbuf; 

  iconv_t cd = iconv_open(to_charset.c_str(), from_charset.c_str()); 
  
  if (cd == 0) return -1;
  
  memset(outbuf, 0, outlen); 
  
  if (iconv(cd, pin, &inlen, pout, &outlen) < 0) 
    return -1; 

  iconv_close(cd); 
#endif
  return 0; 
} 

std::string wstr2str(const std::wstring& wstr)
{
  std::string curLocale = setlocale(LC_ALL, NULL);// curLocale = "C";
  setlocale(LC_ALL, "chs"); 

  const wchar_t* _Source = wstr.c_str();
  size_t _Dsize = 2 * wstr.size() + 1;
  char* _Dest = new char[_Dsize];
  memset(_Dest, 0, _Dsize);
  wcstombs(_Dest, _Source, _Dsize);
  
  std::string result = _Dest;
  delete [] _Dest;

  setlocale(LC_ALL, curLocale.c_str());
  
  return result;
}

std::wstring str2wstr(const std::string& str)
{
  setlocale(LC_ALL, "chs"); 

  const char* _Source = str.c_str();
  size_t _Dsize = str.size() + 1;
  wchar_t *_Dest = new wchar_t[_Dsize];

  wmemset(_Dest, 0, _Dsize);
  mbstowcs(_Dest, _Source, _Dsize);

  std::wstring result = _Dest;
  delete [] _Dest;

  setlocale(LC_ALL, "C");

  return result;
}

}
}
}


