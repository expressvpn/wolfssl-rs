const axios = require('axios');

const USER_AGENT =
  'wolfssl-rs-release-ci (https://github.com/expressvpn/wolfssl-rs)';

async function get_crate_max_version(name) {
  try {
    const resp = await axios.get(`https://crates.io/api/v1/crates/${name}`, {
      headers: { 'User-Agent': USER_AGENT },
    });
    return resp.data.crate.max_version;
  } catch (error) {
    console.error(`Error fetching crate details for ${name}:`, error.message);
    throw error;
  }
}

module.exports = get_crate_max_version;
