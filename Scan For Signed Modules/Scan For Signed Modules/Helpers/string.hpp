#ifndef _STRING_HPP_
#define _STRING_HPP_

#include <string>      // std::string, std::wstring
#include <algorithm>   // std::copy  

std::wstring StringToWString(const std::string& s)
{
    std::wstring temp(s.length(), L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}


std::string WStringToString(const std::wstring& s)
{
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

#endif // _STRING_HPP_
