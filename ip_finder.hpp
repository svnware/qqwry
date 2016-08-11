#ifndef __COMMON_ip_finder_HPP_
#define __COMMON_ip_finder_HPP_
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)
#include <Windows.h>
#endif
#include <boost/cstdint.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

namespace is {
namespace common{
namespace location{
#define INET6_ADDRSTRLEN 46  

class ip_finder;
typedef boost::shared_ptr<ip_finder> ip_finder_ptr;

// only Linux
class ip_finder : boost::noncopyable
{
public:
  ip_finder();
  ~ip_finder();

  int initialize(const std::string& file);
  void destroy();

    
  // 获得ip所属省、市
  // 返回数据UTF8编码
  bool get_ipinfo(const std::string& ipstr, std::string& province, std::string& city);

  // 获得ip所属省市
  // 返回数据UTF8编码
  bool get_ipinfo(const std::string& ipstr, std::string& provincecity);

  // 获取IP数据库原始信息
  // 返回数据GB2312编码
  bool get_ip_original_info(const std::string& ipstr, std::string& country, std::string& area, bool utf8 = false);

  int utf8togb2312(const std::string& instr, std::string& outstr);
  int gb2312toutf8(const std::string& instr, std::string& outstr);

  std::string wstr2str(const std::wstring& wstr);
  std::wstring str2wstr(const std::string& str);

protected:
  /**  
   * 返回地区信息  
   *  
   * @char *pos 地区的指针  
   * @return char *  
   */ 
  unsigned char* get_area(unsigned char* search, unsigned char* pos);

  //将读取的4个字节转化为长整型数  
  boost::uint32_t get_long4(const unsigned char* pos);

  //将读取的3个字节转化为长整型数  
  boost::uint32_t get_long3(const unsigned char* pos);

  int code_convert(const std::string& from_charset, const std::string& to_charset, const char* inbuf, size_t inlen, char* outbuf, size_t outlen);

private:
  enum {  
    REDIRECT_MODE_0 = 0x00, // 没有区域信息
    REDIRECT_MODE_1 = 0x01, // 重定向模式1 偏移量后无地区名
                          // 标志字节为1，表示国家和区域信息都被同时重定向
    REDIRECT_MODE_2 = 0x02, // 重定向模式2 偏移量后有地区名  
                          // 标志字节为2，表示国家信息被重定向
  }; 

  // 结果集
  typedef struct   
  {  
    unsigned char *pcountry_;
    unsigned char *parea_;
    unsigned char beginip[INET6_ADDRSTRLEN]; // 用户IP所在范围的开始地址 
    unsigned char endip[INET6_ADDRSTRLEN];   // 用户IP所在范围的结束地址
  } location_t;  

  unsigned char* pshare_;  // 共享内存指针
  unsigned char* pbegin_;  // 第一条记录指针
  unsigned char* pend_;		 // 最后一条记录指针
#if defined(WIN32) || defined(_WIN32) || defined(WINDOWS) || defined(_WINDOWS)
  HANDLE hFileMap_;
#endif

  boost::uint32_t total_record_; // 总记录数

  std::string strgb_province_;
  std::string strgb_city_;
  std::string strgb_xizang_;
  std::string strgb_xinjiang_;
  std::string strgb_neimeng_;
  std::string strgb_ningxia_;
  std::string strgb_guangxi_;
};

}
}
}
#endif
