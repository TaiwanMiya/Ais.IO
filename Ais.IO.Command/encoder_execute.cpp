#include "encoder_execute.h"

void encoder_execute::ExecuteEncoder(const std::string mode, const Command& cmd) {
    size_t inputLength = cmd.value.size();
    size_t outputLength;
    if (mode == "--base16") {
        outputLength = inputLength * 2 + 1;
    }
    else if (mode == "--base32") {
        outputLength = ((inputLength + 4) / 5) * 8 + 1;
    }
    else if (mode == "--base64") {
        outputLength = ((inputLength + 2) / 3) * 4 + 1;
    }
    else if (mode == "--base85") {
        outputLength = ((inputLength + 3) / 4) * 5 + 1;
    }
    else {
        std::cerr << Warn("Wrong Pattern: ") << Ask(mode) << "\n";
        return;
    }
    std::vector<char> outputBuffer(outputLength, '\0');
    int resultCode = -4;
    std::string encodeType = mode.substr(1) + "-" + cmd.type.substr(1);
    std::string display = ToLetter(mode.substr(2) + cmd.type.substr(1));
    const unsigned char* value = reinterpret_cast<unsigned char*>(const_cast<char*>(cmd.value.c_str()));
    if (encodeType == "-base16-encode")
        resultCode = ((Base16Encode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base32-encode")
        resultCode = ((Base32Encode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base64-encode")
        resultCode = ((Base64Encode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base85-encode")
        resultCode = ((Base85Encode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base16-decode")
        resultCode = ((Base16Decode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base32-decode")
        resultCode = ((Base32Decode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base64-decode")
        resultCode = ((Base64Decode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (encodeType == "-base85-decode")
        resultCode = ((Base85Decode)EncodeFunctions.at(encodeType))(value, inputLength, outputBuffer.data(), outputLength);
    if (resultCode < 0)
        std::cerr << Error("Failed to process ") << Ask(cmd.type) << Error(" for ") << Ask(mode) << Error("\nCode: ") << Ask(std::to_string(resultCode)) << "\n";
    else
        std::cout << Hint("<" + display + ">\n") << Ask(outputBuffer.data()) << Hint("\nInput Length: [") << Ask(std::to_string(inputLength)) << Hint("]\nOutput Length: [") << Ask(std::to_string(resultCode)) << Hint("]\n");
    std::cout << Mark(display + " Action Completed!") << std::endl;
}