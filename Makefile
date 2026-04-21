CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Iinclude -pthread -O3

SRC_DIR = src
INC_DIR = include
TEST_DIR = tests
OBJ_DIR = build

SOURCES = $(SRC_DIR)/EnvParser.cpp \
          $(SRC_DIR)/CaesarCipher.cpp \
          $(SRC_DIR)/VigenereCipher.cpp \
          $(SRC_DIR)/AtbashCipher.cpp \
          $(SRC_DIR)/RailFenceCipher.cpp \
          $(SRC_DIR)/AffineCipher.cpp \
          $(SRC_DIR)/BeaufortCipher.cpp \
          $(SRC_DIR)/EnigmaCipher.cpp \
          $(SRC_DIR)/BigInt.cpp \
          $(SRC_DIR)/RSACipher.cpp \
          $(SRC_DIR)/ECCipher.cpp \
          $(SRC_DIR)/LWECipher.cpp \
          $(SRC_DIR)/AESCipher.cpp \
          $(SRC_DIR)/Dictionary.cpp \
          $(SRC_DIR)/TuringBombe.cpp \
          $(SRC_DIR)/SHA256.cpp \
          $(SRC_DIR)/StatisticalAnalyzer.cpp \
          $(SRC_DIR)/KasiskiEngine.cpp \
          $(SRC_DIR)/KeyDerivation.cpp \
          $(SRC_DIR)/FileCarver.cpp \
          $(SRC_DIR)/PCAPParser.cpp \
          $(SRC_DIR)/CoreUtils.cpp \
          $(SRC_DIR)/ClassicalHandlers.cpp \
          $(SRC_DIR)/MechanicalHandlers.cpp \
          $(SRC_DIR)/ModernHandlers.cpp \
          $(SRC_DIR)/AsymmetricHandlers.cpp \
          $(SRC_DIR)/ForensicHandlers.cpp

OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(OBJ_DIR)/%.o,$(SOURCES))

MAIN_APP = decypher_app
TEST_APP = decypher_test

all: $(MAIN_APP) $(TEST_APP)

$(MAIN_APP): $(OBJ_DIR)/main.o $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(TEST_APP): $(OBJ_DIR)/test_main.o $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJ_DIR)/main.o: $(SRC_DIR)/main.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/test_main.o: $(TEST_DIR)/test_main.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp | $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

run: $(MAIN_APP)
	./$(MAIN_APP)

test: $(TEST_APP)
	./$(TEST_APP)

clean:
	rm -rf $(OBJ_DIR) $(MAIN_APP) $(TEST_APP) temp_dict.txt

.PHONY: all run test clean