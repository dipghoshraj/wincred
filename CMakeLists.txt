cmake_minimum_required(VERSION 3.16)
project(facecred CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenCV REQUIRED)            # needs >= 4.5.4 (FaceDetectorYN / FaceRecognizerSF)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(facecred src/main.cpp)
target_include_directories(facecred PRIVATE ${OpenCV_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS})
target_link_libraries(facecred PRIVATE ${OpenCV_LIBS} ${SODIUM_LIBRARIES})
target_compile_options(facecred PRIVATE -Wall -Wextra -Wpedantic -D_FORTIFY_SOURCE=2 -fstack-protector-strong)
