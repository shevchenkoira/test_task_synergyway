import React, {useEffect} from "react";
import {Container} from "react-bootstrap";
import axios from "axios";
import {BASE_URL} from "../../utils/utils";
import {useNavigate} from "react-router-dom";

import "./GroupsList.css"

const Block_groups = (props) => {

    const navigate = useNavigate();
    const id = props.id

    const handlerNavigatorEditGroup = () => {
        navigate("/edit_group/" + props.id)
    }

    const handlerNavigatorGroupsList = () => {
        navigate("/groups/")
    }

    const DeleteGroup = () => {
        axios({
            method: "delete",
            url: BASE_URL + '/group/' + props.id + "/"
        })
            .then((response) => {
                handlerNavigatorGroupsList()
                window.location.reload()
            })
            .catch((error) => {
                if (error.response) {
                    console.log(error.response);
                    console.log(error.response.status);
                    console.log(error.response.headers);
                }
                alert("You can`t delete this group while it has participants!");
            })
    }

    return (
        <tr>
            <td>{props.id}</td>
            <td>{props.name}</td>
            <td>{props.description}</td>
            <td>{props.users}</td>
            <td className="group-list_actions_block">
                <div className="group-list_edit">
                    <p onClick={handlerNavigatorEditGroup}>
                        Edit
                    </p>
                </div>
                <div className="group-list_delete">
                    <p onClick={DeleteGroup}>
                        Delete
                    </p>
                </div>
            </td>
        </tr>
    );
}

const GroupsList = () => {
    const [groups, setGroups] = React.useState([]);
    useEffect(() => {
        getgroups();
    }, []);

    function getgroups() {
        axios.get(BASE_URL + "/groups/")
            .then((response) => {
                console.log(response.data)
                const data = response.data
                setGroups(data)
            })
            .catch((error) => {
                if (error.response) {
                    console.log(error.response);
                    console.log(error.response.status);
                    console.log(error.response.headers);
                }
            })
    }


    const getAll = () => {
        let result = []

        for (const group of Object.values(groups)) {
            result.push(<Block_groups
                name={group.name}
                description={group.description}
                id={group.id}
                users={group.users.length}
            />)
        }
        return result
    }

    const navigate = useNavigate();

    const handlerNavigatorAddGroup = () => {
        navigate("/add_group")
    }

    return (
        <Container fluid={true}>
            <div className="group-list_whole_page">
                <div className="group-list_header">
                    <div className="group-list_block_title">
                        <h1>All groups</h1>
                    </div>
                </div>
                <div className="group-list_list_of_all">
                    {
                        groups.length === 0 ?
                            (<div className="group-list_no_groups">
                                <p>
                                    There are no groups here. You can register your first
                                    <b>
                                        <div className="group-list_add">
                                            <p onClick={handlerNavigatorAddGroup}>
                                                one
                                            </p>
                                        </div>
                                        here</b>.
                                </p>
                            </div>)
                            :
                            (
                                <div className="group-list_main_component">
                                    <div className="group-list_add">
                                        <p onClick={handlerNavigatorAddGroup}>
                                            Add group
                                        </p>
                                    </div>
                                    <table className="group-list_table">
                                        <thead>
                                        <tr>
                                            <th>№</th>
                                            <th>Name</th>
                                            <th>Description</th>
                                            <th>Participant</th>
                                            <th>Actions</th>
                                        </tr>
                                        </thead>
                                        <tbody>
                                        {
                                            getAll()
                                        }
                                        </tbody>

                                    </table>
                                </div>
                            )
                    }
                </div>
            </div>
        </Container>
    )
}


export default GroupsList;