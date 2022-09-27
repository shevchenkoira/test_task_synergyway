import React from "react";
import axios from "axios";
import Container from 'react-bootstrap/Container';
import {BASE_URL} from "../../utils/utils";
import "./AddGroup.css";
import {useNavigate} from "react-router-dom";

const AddUser = () => {
    const [formValue, setFormValue] = React.useState({
        name: "",
        description: "",
    });

    const navigate = useNavigate()

    const handleSubmit = async (event) => {
        event.preventDefault()
        const keyArray = ["input_name", "input_description"]
        for (const currentKey of keyArray) {
            let currentElement = document.querySelector(`[name='${currentKey}']`);
            let currentErrorMessage = currentElement.parentElement.querySelector("p");
            currentElement.classList.remove("add-group_validation_error");
            currentErrorMessage.classList.remove("error_message_shown");
        }
        console.log(JSON.stringify(formValue))

        const formData = new FormData()
        formData.append("name", formValue.name)
        formData.append("description", formValue.description)

        await axios({
            method: "post",
            url: BASE_URL + "/groups/",
            data: formData
        }).then(response => {
            navigate("/groups/")
        }).catch(error => {
            const errors = error.response.data
            console.log(errors)
            for (const currentKey of Object.keys(errors)) {
                setError(currentKey, errors[currentKey])
            }
            window.scrollTo(0, 0)
        });
    }

    const setError = (key, error_message) => {
        key = "input_"+ key;
        let currentElement = document.querySelector(`[name='${key}']`);
        let currentErrorMessage = currentElement.parentElement.querySelector("p");
        currentElement.classList.add("add-group_validation_error");
        currentErrorMessage.classList.add("error_message_shown");
        currentErrorMessage.innerText = error_message;
    }

    const handleChange = (event) => {
        setFormValue({
            ...formValue,
            [event.target.name.replace("input_", "")]: event.target.value
        });
    }

    return (
        <Container fluid={true}>
            <form onSubmit={handleSubmit} className="add-group_form">
                <div className="add-group_wrapper">
                    <div className="add-group_midline_block">
                        <hr/>
                        <div className="add-group_midline_header_block">
                            <h1 className="add-group_midline_header">Create group</h1>
                        </div>
                        <hr/>
                    </div>
                    <div className="add-group_form_section">
                        <div className="add-group_form_section_wrapper">
                            <div className="add-group_form_item">
                                <p className="add-group_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_name"
                                    className="add-group_form__input"
                                    placeholder={"Name"}
                                    value={formValue.name}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="add-group_form_item">
                                <p className="add-group_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_description"
                                    className="add-group_form__input"
                                    placeholder={"Description"}
                                    value={formValue.description}
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                        <hr/>
                        <div className="add-group_form_section">
                            <div className="add-group_submit_button_block">
                                <button type="submit"
                                        className="add-group_form__input__button"
                                >Submit
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </Container>
)

}

export default AddUser;