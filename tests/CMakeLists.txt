add_executable(securewipe_tests
    ../src/cli_application.cpp
    capability_inspection_tests.cpp
    test_secure_wipe.cpp
)

target_link_libraries(securewipe_tests PRIVATE securewipe_lib CLI11::CLI11)

target_include_directories(securewipe_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_features(securewipe_tests PRIVATE cxx_std_20)

if(MSVC)
    target_compile_options(securewipe_tests PRIVATE /W4 /permissive-)
else()
    target_compile_options(securewipe_tests PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_test(NAME securewipe_tests COMMAND securewipe_tests)
add_test(NAME securewipe_help COMMAND $<TARGET_FILE:securewipe> --help)
add_test(NAME securewipe_inspect_requires_path COMMAND $<TARGET_FILE:securewipe> inspect)
add_test(NAME securewipe_wipe_rejects_dir_flags COMMAND $<TARGET_FILE:securewipe> wipe sample.txt --dry-run)
add_test(NAME securewipe_unknown_option COMMAND $<TARGET_FILE:securewipe> wipe sample.txt --bogus)
add_test(NAME securewipe_invalid_passes COMMAND $<TARGET_FILE:securewipe> wipe sample.txt --passes 0)
add_test(NAME securewipe_invalid_pattern COMMAND $<TARGET_FILE:securewipe> wipe sample.txt --pattern bogus)
set_tests_properties(securewipe_inspect_requires_path PROPERTIES WILL_FAIL TRUE)
set_tests_properties(securewipe_wipe_rejects_dir_flags PROPERTIES WILL_FAIL TRUE)
set_tests_properties(securewipe_unknown_option PROPERTIES WILL_FAIL TRUE)
set_tests_properties(securewipe_invalid_passes PROPERTIES WILL_FAIL TRUE)
set_tests_properties(securewipe_invalid_pattern PROPERTIES WILL_FAIL TRUE)
