cmake_minimum_required(VERSION 3.11)
project(SimpleClient)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(Boost_USE_STATIC_LIBS OFF) 
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

include_directories(include)

find_package(OpenSSL REQUIRED)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})

add_subdirectory(ex/ftxui EXCLUDE_FROM_ALL)
add_executable(${PROJECT_NAME} src/main.cpp)
target_include_directories(${PROJECT_NAME} PRIVATE src)
target_link_libraries(${PROJECT_NAME} PRIVATE ftxui::screen PRIVATE ftxui::dom PRIVATE ftxui::component PRIVATE OpenSSL::SSL OpenSSL::Crypto PRIVATE ${Boost_LIBRARIES})
