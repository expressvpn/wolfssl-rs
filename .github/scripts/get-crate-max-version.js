const axios = require('axios');

async function get_crate_max_version(name) {
  try {
    const resp = await axios(`https://crates.io/api/v1/crates/${name}`);
    return resp.data.crate.max_version;
  } catch (error) {
    console.error(`Error fetching crate details for ${name}:`, error.message);
    throw error;
  }
}

module.exports = get_crate_max_version;
