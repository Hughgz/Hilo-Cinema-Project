import React, { useState, useEffect } from "react";
import { useDispatch } from "react-redux";
import {
    Modal,
    ModalOverlay,
    ModalContent,
    ModalHeader,
    ModalCloseButton,
    ModalBody,
    ModalFooter,
    FormControl,
    FormLabel,
    Input,
    Select,
    Button,
    useColorModeValue,
    FormErrorMessage,
    Stack,
} from "@chakra-ui/react";
import PropTypes from "prop-types";
import { addTheater, fetchTheaters } from "reduxHilo/actions/theaterAction";  // Adjust the imports for theaters

const CreateTheater = ({ isOpen, onClose }) => {
    const dispatch = useDispatch();

    const [formData, setFormData] = useState({
        name: "",
        city: "",
        detailAddress: "",
        hotline: "",
        status: "",
    });

    const [errors, setErrors] = useState({});

    const validate = () => {
        let validationErrors = {};

        if (!formData.name) {
            validationErrors.name = "Name is required";
        }
        if (!formData.city) {
            validationErrors.city = "City is required";
        }
        if (!formData.detailAddress) {
            validationErrors.detailAddress = "Detail Address is required";
        }
        if (!formData.hotline) {
            validationErrors.hotline = "Hotline is required";
        }
        if (!formData.status) {
            validationErrors.status = "Status is required";
        }

        return validationErrors;
    };

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormData({ ...formData, [name]: value });
        setErrors({ ...errors, [name]: "" });  // Clear the error for the current field
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        const validationErrors = validate();
        if (Object.keys(validationErrors).length > 0) {
            setErrors(validationErrors);
        } else {
            try {
                // Dispatch the addTheater action with formData
                await dispatch(addTheater(formData));
                alert("Theater added successfully");
                onClose(); // Close modal after successful addition
                dispatch(fetchTheaters()); // Refresh the theater list
            } catch (error) {
                console.error("Error saving theater:", error.response ? error.response.data : error.message);
            }
        }
    };

    const formBackgroundColor = useColorModeValue("white", "gray.700");
    const inputBackgroundColor = useColorModeValue("gray.100", "gray.600");
    const textColor = useColorModeValue("black", "white");

    return (
        <Modal isOpen={isOpen} onClose={onClose}>
            <ModalOverlay />
            <ModalContent>
                <ModalHeader>Add New Theater</ModalHeader>
                <ModalCloseButton />
                <ModalBody pb={6}>
                    <form onSubmit={handleSubmit}>
                        <Stack spacing={4}>
                            <FormControl id="name" isInvalid={errors.name}>
                                <FormLabel color={textColor}>Name</FormLabel>
                                <Input
                                    type="text"
                                    name="name"
                                    value={formData.name}
                                    onChange={handleChange}
                                    bg={inputBackgroundColor}
                                    border={0}
                                    color={textColor}
                                    _placeholder={{ color: "gray.500" }}
                                />
                                {errors.name && <FormErrorMessage>{errors.name}</FormErrorMessage>}
                            </FormControl>
                            <FormControl id="city" isInvalid={errors.city}>
                                <FormLabel color={textColor}>City</FormLabel>
                                <Input
                                    type="text"
                                    name="city"
                                    value={formData.city}
                                    onChange={handleChange}
                                    bg={inputBackgroundColor}
                                    border={0}
                                    color={textColor}
                                    _placeholder={{ color: "gray.500" }}
                                />
                                {errors.city && <FormErrorMessage>{errors.city}</FormErrorMessage>}
                            </FormControl>
                            <FormControl id="detailAddress" isInvalid={errors.detailAddress}>
                                <FormLabel color={textColor}>Detail Address</FormLabel>
                                <Input
                                    type="text"
                                    name="detailAddress"
                                    value={formData.detailAddress}
                                    onChange={handleChange}
                                    bg={inputBackgroundColor}
                                    border={0}
                                    color={textColor}
                                    _placeholder={{ color: "gray.500" }}
                                />
                                {errors.detailAddress && <FormErrorMessage>{errors.detailAddress}</FormErrorMessage>}
                            </FormControl>
                            <FormControl id="hotline" isInvalid={errors.hotline}>
                                <FormLabel color={textColor}>Hotline</FormLabel>
                                <Input
                                    type="text"
                                    name="hotline"
                                    value={formData.hotline}
                                    onChange={handleChange}
                                    bg={inputBackgroundColor}
                                    border={0}
                                    color={textColor}
                                    _placeholder={{ color: "gray.500" }}
                                />
                                {errors.hotline && <FormErrorMessage>{errors.hotline}</FormErrorMessage>}
                            </FormControl>
                            <FormControl id="status" isInvalid={errors.status}>
                                <FormLabel color={textColor}>Status</FormLabel>
                                <Select
                                    name="status"
                                    value={formData.status}
                                    onChange={handleChange}
                                    bg={inputBackgroundColor}
                                    border={0}
                                    color={textColor}
                                >
                                    <option value="Active">Active</option>
                                    <option value="Inactive">Inactive</option>
                                </Select>
                                {errors.status && <FormErrorMessage>{errors.status}</FormErrorMessage>}
                            </FormControl>
                        </Stack>
                    </form>
                </ModalBody>
                <ModalFooter>
                    <Button colorScheme="blue" onClick={handleSubmit}>
                        Save
                    </Button>
                    <Button onClick={onClose}>Cancel</Button>
                </ModalFooter>
            </ModalContent>
        </Modal>
    );
};

CreateTheater.propTypes = {
    isOpen: PropTypes.bool.isRequired,
    onClose: PropTypes.func.isRequired,
};

export default CreateTheater;