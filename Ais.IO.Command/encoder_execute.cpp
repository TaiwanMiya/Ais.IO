#include "encoder_execute.h"
#include <functional>
#include <filesystem>
#include "cryptography_libary.h"

void encoder_execute::ExecuteEncoder(const std::string mode, Command& cmd) {
    size_t size = 0;
    std::vector<unsigned char> buffer(0);
    std::filesystem::path inputPath;
    std::filesystem::path outputPath;
    if (IsInput)
        cmd.value = InputContent;
    else if (!cmd.input.empty()) {
        encoder_execute::SetInput(cmd, size, buffer);
        inputPath = std::filesystem::absolute(cmd.input);
        if (!buffer.data()) {
            std::cerr << Error("Failed to read input file: ") << Ask(cmd.input) << "\n";
            return;
        }
    }
    else if (cmd.value.empty()) {
        std::cerr << Error("No input data provided for encoding/decoding.\n");
        return;
    }

    size_t inputLength = size > 0 ? size : cmd.value.size();
    size_t outputLength = cryptography_libary::CalculateEncodeLength(mode, inputLength);
    if (outputLength == 0) {
        std::cerr << Warn("Invalid mode: ") << Ask(mode) << "\n";
        return;
    }

    std::vector<unsigned char> outputBuffer(outputLength);
    int resultCode = -1;

    std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
    std::string display = ToLetter(mode.substr(2)) + " " + ToLetter(cmd.type.substr(1));

    if (encodeType.size() >= 7 && encodeType.substr(encodeType.size() - 7) == "-decode" && buffer.size() > 0) {
        buffer.erase(std::remove(buffer.begin(), buffer.end(), '\0'), buffer.end());
        inputLength = buffer.size();
        outputLength = cryptography_libary::CalculateEncodeLength(mode, inputLength);
        outputBuffer.resize(outputLength);
    }
    const unsigned char* inputData = buffer.data() ? buffer.data() : reinterpret_cast<const unsigned char*>(cmd.value.c_str());

    if (encodeType == "-base10-encode")
        resultCode = ((Base10Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base16-encode")
        resultCode = ((Base16Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base32-encode")
        resultCode = ((Base32Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base58-encode")
        resultCode = ((Base58Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base62-encode")
        resultCode = ((Base62Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base64-encode")
        resultCode = ((Base64Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base85-encode")
        resultCode = ((Base85Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);
    if (encodeType == "-base91-encode")
        resultCode = ((Base91Encode)EncodeFunctions.at(encodeType))(inputData, inputLength, reinterpret_cast<char*>(outputBuffer.data()), outputLength);

    if (encodeType == "-base10-decode")
        resultCode = ((Base10Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base16-decode")
        resultCode = ((Base16Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base32-decode")
        resultCode = ((Base32Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base58-decode")
        resultCode = ((Base58Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base62-decode")
        resultCode = ((Base62Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base64-decode")
        resultCode = ((Base64Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base85-decode")
        resultCode = ((Base85Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base91-decode")
        resultCode = ((Base91Decode)EncodeFunctions.at(encodeType))(reinterpret_cast<const char*>(inputData), inputLength, outputBuffer.data(), outputLength);

    if (resultCode < 0) {
        std::cerr << Error("Encoding/Decoding failed for ") << Ask(mode) << Error(" with code: ") << Ask(std::to_string(resultCode)) << "\n";
        std::string error_message = cryptography_libary::GetBaseErrorCode(resultCode);
        std::cerr << Error(display + " Error: " + error_message) << std::endl;
    }
    else {
        if (!cmd.output.empty()) {
            if (resultCode > outputBuffer.size()) {
                std::cerr << Error("Output buffer overflow detected.\n");
                return;
            }
            buffer.resize(resultCode);
            std::memcpy(buffer.data(), outputBuffer.data(), resultCode);
            encoder_execute::SetOutput(cmd, static_cast<size_t>(resultCode), buffer);
            outputPath = std::filesystem::absolute(cmd.output);
        }
        if (!IsRowData) {
            std::cout << Hint("<" + display + ">\n");
            if (outputPath.empty())
                std::cout << Ask(std::string(reinterpret_cast<char*>(outputBuffer.data()))) << "\n";
            if (!inputPath.empty())
                std::cout << Hint("Input Path:\n") << Ask(inputPath.string()) << "\n";
            if (!outputPath.empty())
                std::cout << Hint("Output Path:\n") << Ask(outputPath.string()) << "\n";
            std::cout << Hint("Input Length: [") << Ask(std::to_string(inputLength)) << Hint("]") << std::endl;
            std::cout << Hint("Output Length: [") << Ask(std::to_string(resultCode)) << Hint("]") << std::endl;
        }
        else
            std::cout << Ask(std::string(reinterpret_cast<char*>(outputBuffer.data()))) << std::endl;
    }

    if (!IsRowData)
        std::cout << Mark(display + " Action Completed!") << std::endl;
    buffer.clear();
}

void encoder_execute::SetInput(Command& cmd, size_t& size, std::vector<unsigned char>& buffer) {
    if (cmd.input.empty()) {
        std::cerr << Error("Input file path is empty.") << std::endl;
        return;
    }
    std::ifstream file(cmd.input, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << Error("Failed to open for file: " + cmd.input) << std::endl;
        return;
    }

    size = file.tellg();
    file.seekg(0, std::ios::beg);
    buffer.clear();
    buffer.resize(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cerr << Error("Failed to read file: " + cmd.input) << std::endl;
        buffer.clear();
    }
    while ((!buffer.empty() && buffer.back() == '\n') ||
           (!buffer.empty() && buffer.back() == '\r') ||
           (!buffer.empty() && buffer.back() == '\0')) {
        if (!buffer.empty() && buffer.back() == '\0')
            buffer.pop_back();
        if (!buffer.empty() && buffer.back() == '\n')
            buffer.pop_back();
        if (!buffer.empty() && buffer.back() == '\r')
            buffer.pop_back();
    }

    std::vector<unsigned char> cleaned_output;
    if (buffer.size() >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
        buffer.erase(buffer.begin(), buffer.begin() + 2);	// UTF-16 LE BOM
    else if (buffer.size() >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF)
        buffer.erase(buffer.begin(), buffer.begin() + 3);	// UTF-16 BE BOM
    else if (buffer.size() >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF) {
        buffer.erase(buffer.begin(), buffer.begin() + 3);	// UTF-8 BOM
        goto end;
    }
    else
        goto end;

    for (size_t i = 0; i < buffer.size(); ++i) {
        if (buffer[i] == '\0' && i % 2 != 0)
            continue;
        cleaned_output.push_back(buffer[i]);
    }
    buffer = std::move(cleaned_output);

end:
    size = buffer.size();
    file.close();
}

void encoder_execute::SetOutput(Command& cmd, size_t size, std::vector<unsigned char>& buffer) {
    if (!buffer.data() || cmd.output.empty()) {
        std::cerr << Error("No binary data or output path provided for writing.\n");
        return;
    }
    std::ofstream file(cmd.output, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << Error("Failed to open file: " + cmd.output) << std::endl;
        return;
    }
    file.write(reinterpret_cast<const char*>(buffer.data()), size);
    if (!file)
        std::cerr << Error("Failed to write data to file: " + cmd.output) << std::endl;
    buffer.clear();
    file.close();
}