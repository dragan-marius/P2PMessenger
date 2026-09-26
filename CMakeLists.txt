cmake_minimum_required(VERSION 3.19)
project(P2PMessenger LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)

qt_standard_project_setup()

qt_add_executable(P2PMessenger
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    ReliableUDPSocket.cpp
    ReliableUDPSocket.h
)

target_link_libraries(P2PMessenger
    PRIVATE
        Qt::Core
        Qt::Widgets ws2_32
        Qt6::Network
)

install(TARGETS P2PMessenger
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET P2PMessenger
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
