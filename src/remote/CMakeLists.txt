add_executable(veh-remote-runner main.cpp work_owner.cpp ../adapter/pipe_client.cpp)
target_include_directories(veh-remote-runner PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(veh-remote-runner PRIVATE veh_remote veh_common nlohmann_json)
target_compile_definitions(veh-remote-runner PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
